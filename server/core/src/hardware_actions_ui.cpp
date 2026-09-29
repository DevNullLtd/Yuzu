/// @file hardware_actions_ui.cpp
/// The Hardware CI record's Actions lens — PURE renderers for the generic action
/// runner (every plugin.action a connected agent reports, grouped by plugin,
/// class-badged from the compile-time capability catalogue, each with a
/// schema-derived parameter form) and its dispatch-result panel. Dispatch itself
/// goes through the EXISTING `POST /api/command` route (command_routes.cpp) via
/// the `hwRunAction` JS helper in guardian_page_ui.cpp — this file only renders.

#include "hardware_routes.hpp"

#include "result_parsing.hpp" // columns_for_plugin, split_fields
#include "web_utils.hpp"      // html_escape, agent_error_display

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace yuzu::server {

namespace {

std::string esc(const std::string& s) { return html_escape(s); }

std::string url_encode(const std::string& s) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0f]);
        }
    }
    return out;
}

const char* class_label(DispatchClass c) {
    switch (c) {
        case DispatchClass::ReadOnly: return "Read-only";
        case DispatchClass::Mutating: return "Mutating";
        case DispatchClass::Destructive: return "Destructive";
    }
    return "Unknown";
}

const char* class_css(DispatchClass c) {
    switch (c) {
        case DispatchClass::ReadOnly: return "hw-badge ro";
        case DispatchClass::Mutating: return "hw-badge mut";
        case DispatchClass::Destructive: return "hw-badge dst";
    }
    return "hw-badge";
}

std::string field_html(const ActionFormField& f) {
    const std::string req = f.required ? " *" : "";
    std::string h = "<div class=\"hw-fld\"><label>" + esc(f.name) + esc(req) + "</label>";
    const std::string input_name = "p_" + f.name;
    if (f.kind == ActionFormField::Kind::Enum) {
        h += "<select name=\"" + esc(input_name) + "\">";
        if (!f.required) h += "<option value=\"\"></option>";
        for (const auto& v : f.enum_values) {
            const bool sel = v == f.default_value;
            h += "<option value=\"" + esc(v) + "\"" + (sel ? " selected" : "") + ">" + esc(v) +
                 "</option>";
        }
        h += "</select>";
    } else if (f.kind == ActionFormField::Kind::Boolean) {
        h += "<select name=\"" + esc(input_name) + "\">"
             "<option value=\"\"></option>"
             "<option value=\"true\"" + std::string(f.default_value == "true" ? " selected" : "") +
             ">true</option>"
             "<option value=\"false\"" + std::string(f.default_value == "false" ? " selected" : "") +
             ">false</option></select>";
    } else {
        const char* type = f.sensitive ? "password"
                          : f.kind == ActionFormField::Kind::Integer ? "number"
                          : f.kind == ActionFormField::Kind::Number ? "number"
                          : "text";
        h += "<input type=\"" + std::string(type) + "\" name=\"" + esc(input_name) +
             "\" value=\"" + esc(f.default_value) + "\" placeholder=\"" + esc(f.description) +
             "\" autocomplete=\"off\">";
    }
    if (!f.description.empty())
        h += "<div class=\"hw-hint\">" + esc(f.description) + "</div>";
    if (f.sensitive)
        h += "<div class=\"hw-hint\">Sent once to the device; never persisted.</div>";
    h += "</div>";
    return h;
}

// The "what do I type here" guide beside every action form (round-2 item 4):
// the manifest-documented inputs (name/type/required/default/constraints/
// description) and a captured example invocation. Honest when nothing is
// documented — the 11 definition-less catalogue actions say so plainly.
std::string syntax_block(const ActionFormSpec& form) {
    std::string h = "<div class=\"hw-syntax\">";
    if (!form.inputs.empty()) {
        h += "<table><thead><tr><th>Input</th><th>Type</th><th>Req</th><th>Default</th>"
             "<th>Constraints</th><th>Description</th></tr></thead><tbody>";
        for (const auto& in : form.inputs) {
            h += "<tr><td><code>" + esc(in.name) + "</code></td><td>" + esc(in.type) + "</td><td>" +
                 (in.required ? "yes" : "no") + "</td><td>" + esc(in.default_value) + "</td><td>" +
                 esc(in.constraints) + "</td><td>" + esc(in.description) + "</td></tr>";
        }
        h += "</tbody></table>";
    }
    if (!form.example.empty())
        h += "<div>Example: <code>" + esc(form.example) + "</code></div>";
    if (form.inputs.empty() && form.example.empty()) {
        h += form.schema_usable
                 ? "<div>Inputs above come from this deployment's instruction definition.</div>"
                 : "<div>No documented parameters &mdash; this action takes none, or accepts "
                   "<code>key=value</code> pairs; see the plugin README.</div>";
    } else if (!form.schema_usable) {
        h += "<div>Syntax: one <code>key=value</code> per line.</div>";
    }
    h += "</div>";
    return h;
}

} // namespace

std::string render_hardware_actions_lens(const std::string& agent_id, const std::string& hostname,
                                         const std::vector<HwActionRow>& rows, HwActionsState state) {
    std::string extra_css = R"css(<style>
  .hw-actctrl{margin:.5rem 0}
  details.hw-plugin{background:var(--surface,#1a2940);border:1px solid var(--border,#2d4068);border-radius:.5rem;margin-bottom:.5rem}
  details.hw-plugin>summary{padding:.5rem .8rem;cursor:pointer;font-weight:700;color:var(--white,#fff);font-size:.82rem}
  .hw-act{padding:.5rem .8rem;border-top:1px solid var(--border,#2d4068)}
  .hw-act-hdr{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
  .hw-act-name{font-family:'JetBrains Mono',Consolas,monospace;font-size:.78rem;color:var(--white,#fff)}
  .hw-act-desc{color:var(--muted,#8fa3bd);font-size:.72rem;flex:1}
  .hw-badge{font-size:.58rem;text-transform:uppercase;letter-spacing:.04em;border-radius:.3rem;padding:.05rem .4rem;font-weight:700}
  .hw-badge.ro{color:var(--green,#4ed27e);border:1px solid rgba(78,210,126,.4)}
  .hw-badge.mut{color:var(--yellow,#ffcc00);border:1px solid rgba(255,204,0,.4)}
  .hw-badge.dst{color:var(--red,#ff5765);border:1px solid rgba(255,87,101,.4)}
  .hw-badge.warn{color:var(--red,#ff5765);border:1px solid rgba(255,87,101,.4)}
  .hw-fld{margin:.4rem 0}
  .hw-fld label{display:block;font-size:.68rem;color:var(--muted,#8fa3bd);margin-bottom:.15rem}
  .hw-fld input,.hw-fld select,.hw-fld textarea{background:var(--bg,#0d1729);border:1px solid var(--border,#2d4068);border-radius:.35rem;color:var(--fg,#cfdbe8);padding:.3rem .5rem;font-size:.76rem;min-width:220px}
  .hw-hint{font-size:.62rem;color:var(--muted,#8fa3bd);margin-top:.1rem}
  .hw-result{margin-top:.5rem;font-size:.76rem}
  .hw-result pre{background:var(--bg,#0d1729);border:1px solid var(--border,#2d4068);border-radius:.4rem;padding:.5rem;overflow:auto;max-height:320px;font-size:.72rem}
  .hw-result table{width:100%;border-collapse:collapse;font-size:.72rem}
  .hw-result th,.hw-result td{border-bottom:1px solid var(--border,#2d4068);padding:.25rem .4rem;text-align:left}
  .hw-syntax{margin:.35rem 0 .2rem;font-size:.66rem;color:var(--muted,#8fa3bd);border-left:2px solid var(--border,#2d4068);padding-left:.5rem}
  .hw-syntax table{border-collapse:collapse;font-size:.64rem;margin-top:.2rem}
  .hw-syntax th,.hw-syntax td{padding:.1rem .45rem .1rem 0;text-align:left;vertical-align:top;border:0}
  .hw-syntax th{color:var(--muted,#8fa3bd);font-weight:600;text-transform:uppercase;letter-spacing:.04em;font-size:.56rem}
  .hw-syntax code{font-family:'JetBrains Mono',Consolas,monospace;color:var(--lightblue,#a5d6ff)}
  .hw-rtool{display:flex;gap:.4rem;align-items:center;flex-wrap:wrap;margin:.3rem 0}
  .hw-rtool input[type=text]{background:var(--bg,#0d1729);border:1px solid var(--border,#2d4068);border-radius:.35rem;color:var(--fg,#cfdbe8);padding:.22rem .45rem;font-size:.72rem;min-width:200px}
  .hw-rtool input.bad{border-color:var(--red,#ff5765)}
  .hw-rtool label{font-size:.66rem;color:var(--muted,#8fa3bd)}
  .hw-rtool .cnt{font-size:.66rem;color:var(--muted,#8fa3bd);margin-left:auto}
  .hw-line{display:block}
  .hw-line.hit{background:rgba(0,188,235,.12)}
</style>)css";

    if (state == HwActionsState::Offline)
        return extra_css + "<div class=\"gp-placeholder\"><b>Actions need a connected agent.</b> "
               "This device is offline — run an action once it reconnects.</div>";
    if (state == HwActionsState::NoExecute)
        return extra_css + "<div class=\"gp-placeholder\">Running actions needs the "
               "<b>Execute</b> permission for this device.</div>";
    if (state == HwActionsState::Unavailable)
        return extra_css + "<div class=\"gp-placeholder\">Actions unavailable on this server.</div>";
    if (rows.empty())
        return extra_css + "<div class=\"gp-placeholder\">This agent reports no plugins.</div>";

    std::string h = extra_css;
    h += "<div class=\"hw-actctrl\"><input class=\"hw-search\" placeholder=\"Filter actions&hellip;\" "
         "oninput=\"gpSearch(this)\" data-gpf=\"hwact\"></div>";

    std::string current_plugin;
    for (const auto& row : rows) {
        if (row.plugin != current_plugin) {
            if (!current_plugin.empty())
                h += "</details>";
            current_plugin = row.plugin;
            h += "<details class=\"hw-plugin\" open><summary>" + esc(row.plugin) + "</summary>";
        }
        const std::string full_name = row.plugin + "." + row.action;
        h += "<div class=\"hw-act\" data-gpf=\"hwact\" data-gpname=\"" + esc(full_name) + " " +
             esc(row.description) + "\">";
        h += "<div class=\"hw-act-hdr\"><span class=\"hw-act-name\">" + esc(full_name) + "</span>";
        if (row.cap) {
            h += "<span class=\"" + std::string(class_css(row.cap->dispatch_class)) + "\">" +
                 class_label(row.cap->dispatch_class) + "</span>";
            if (row.cap->mutability == Mutability::Irreversible)
                h += "<span class=\"hw-badge warn\">Irreversible</span>";
            if (row.cap->execute_gate != ExecuteGate::None &&
                row.cap->execute_gate != ExecuteGate::Unspecified)
                h += "<span class=\"hw-badge warn\">Approval-gated</span>";
        } else {
            h += "<span class=\"hw-badge warn\">" +
                 std::string(row.ambiguous ? "Ambiguous" : "Unclassified") + "</span>";
        }
        h += "<span class=\"hw-act-desc\">" + esc(row.description) + "</span></div>";

        if (!row.cap || row.bad_ident) {
            h += "<div class=\"hw-hint\">Not in the capability catalogue &mdash; dispatch would be "
                 "refused (400). No Run control offered.</div>";
        } else {
            const std::string form_id = "hwf-" + url_encode(row.plugin) + "-" + url_encode(row.action);
            h += "<form id=\"" + form_id + "\" data-plugin=\"" + esc(row.plugin) + "\" data-action=\"" +
                 esc(row.action) + "\" data-agent=\"" + esc(agent_id) + "\" data-host=\"" +
                 esc(hostname) + "\" data-class=\"" +
                 std::string(class_label(row.cap->dispatch_class)) + "\" onsubmit=\"return false\">";
            if (row.form.schema_usable) {
                for (const auto& f : row.form.fields)
                    h += field_html(f);
            } else {
                const std::string ph = row.form.example.empty()
                    ? std::string("key=value")
                    : row.form.example;
                h += "<div class=\"hw-fld\"><label>Parameters (key=value, one per line)</label>"
                     "<textarea name=\"kv\" rows=\"2\" placeholder=\"" + esc(ph) + "\"></textarea></div>";
            }
            h += syntax_block(row.form);
            h += "<button type=\"button\" class=\"gp-btn accent\" onclick=\"hwRunAction(this)\">Run"
                 "</button>";
            h += "<div class=\"hw-result\"></div>";
            h += "</form>";
        }
        h += "</div>";
    }
    if (!current_plugin.empty())
        h += "</details>";
    return h;
}

std::string render_hardware_result_pending(const std::string& agent_id, const std::string& command_id,
                                           const std::string& plugin, int next_attempt) {
    return "<div hx-get=\"/fragments/hardware/ci/result?id=" + url_encode(agent_id) +
           "&command_id=" + url_encode(command_id) + "&plugin=" + url_encode(plugin) +
           "&n=" + std::to_string(next_attempt) +
           "\" hx-trigger=\"load delay:700ms\" hx-swap=\"outerHTML\">"
           "<span class=\"gp-mute\">Waiting for the device to respond&hellip;</span></div>";
}

namespace {

std::string render_output_table_from_json_array(const nlohmann::json& arr) {
    std::vector<std::string> keys;
    for (const auto& row : arr)
        if (row.is_object())
            for (auto it = row.begin(); it != row.end(); ++it)
                if (std::find(keys.begin(), keys.end(), it.key()) == keys.end())
                    keys.push_back(it.key());
    if (keys.empty())
        return "";
    std::string h = "<table><thead><tr>";
    for (const auto& k : keys) h += "<th>" + html_escape(k) + "</th>";
    h += "</tr></thead><tbody>";
    std::size_t n = 0;
    for (const auto& row : arr) {
        if (n++ >= 20000) { h += "<tr><td colspan=\"" + std::to_string(keys.size()) +
                              "\">&hellip; truncated at 20000 rows</td></tr>"; break; }
        h += "<tr>";
        for (const auto& k : keys) {
            std::string v;
            if (row.is_object() && row.contains(k) && !row.at(k).is_null())
                v = row.at(k).is_string() ? row.at(k).get<std::string>() : row.at(k).dump();
            h += "<td>" + html_escape(v) + "</td>";
        }
        h += "</tr>";
    }
    h += "</tbody></table>";
    return h;
}

std::string render_action_output(const std::string& plugin, const std::string& output) {
    if (output.empty())
        return "<div class=\"gp-mute\">(no output)</div>";
    auto parsed = nlohmann::json::parse(output, nullptr, false);
    if (!parsed.is_discarded()) {
        if (parsed.is_array()) {
            std::string tbl = render_output_table_from_json_array(parsed);
            if (!tbl.empty())
                return tbl;
        }
        return "<pre>" + html_escape(parsed.dump(2)) + "</pre>";
    }
    // Not JSON — try the pipe-delimited plugin-output convention.
    const auto& cols = columns_for_plugin(plugin);
    if (cols.size() > 2) {
        std::vector<std::string> lines;
        std::string cur;
        for (char c : output) {
            if (c == '\n') { lines.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
        if (!cur.empty()) lines.push_back(cur);
        bool all_piped = !lines.empty();
        for (const auto& l : lines)
            if (!l.empty() && l.find('|') == std::string::npos) { all_piped = false; break; }
        if (all_piped) {
            std::string h = "<table><thead><tr>";
            for (const auto& c : cols) h += "<th>" + html_escape(c) + "</th>";
            h += "</tr></thead><tbody>";
            for (const auto& l : lines) {
                if (l.empty()) continue;
                auto fields = split_fields(plugin, l);
                h += "<tr>";
                for (const auto& f : fields) h += "<td>" + html_escape(f) + "</td>";
                h += "</tr>";
            }
            h += "</tbody></table>";
            return h;
        }
    }
    // One span per line so the client-side filter can hide non-matching lines and
    // count hits; the store already caps a response at 2 MiB (kMaxIngestBytes), so
    // the only cap here is the same 2 MiB defensive ceiling.
    constexpr std::size_t kMaxRender = 2ull * 1024 * 1024;
    std::string_view v = output.size() > kMaxRender ? std::string_view(output).substr(0, kMaxRender)
                                                     : std::string_view(output);
    std::string h = "<pre>";
    std::size_t start = 0;
    while (start <= v.size()) {
        const auto nl = v.find('\n', start);
        const std::string_view line = v.substr(start, nl == std::string_view::npos ? std::string_view::npos : nl - start);
        h += "<span class=\"hw-line\">" + html_escape(std::string(line)) + "</span>";
        if (nl == std::string_view::npos)
            break;
        start = nl + 1;
    }
    if (output.size() > kMaxRender)
        h += "<span class=\"hw-line\">… truncated at 2 MiB</span>";
    h += "</pre>";
    return h;
}

} // namespace

std::string render_hardware_action_result(const std::string& plugin, const std::string& action,
                                          const HwActionResultView& view) {
    std::string h = "<div class=\"hw-result\">";
    switch (view.phase) {
        case HwActionResultView::Phase::Pending:
            h += "<span class=\"gp-mute\">Waiting&hellip;</span>";
            break;
        case HwActionResultView::Phase::Rendered:
            if (view.output.rfind("error|", 0) == 0) {
                h += "<div class=\"gp-err\">" + html_escape(agent_error_display(view.output)) + "</div>";
            } else {
                // Search / regex / CSV toolbar (round-2 items 7 and 8) — client-side over
                // the rendered rows or lines; export honours the current filter.
                h += "<div class=\"hw-rtool\">"
                     "<input type=\"text\" placeholder=\"Search output\u2026\" oninput=\"hwFilterResult(this)\">"
                     "<label><input type=\"checkbox\" onchange=\"hwFilterResult(this)\"> regex</label>"
                     "<button type=\"button\" class=\"gp-btn\" data-name=\"" + html_escape(plugin + "-" + action) +
                     "\" onclick=\"hwExportCsv(this)\">Export CSV</button>"
                     "<button type=\"button\" class=\"gp-btn\" onclick=\"hwCopyResult(this)\">Copy</button>"
                     "<span class=\"cnt\"></span></div>";
                h += "<div class=\"hw-rbody\">" + render_action_output(plugin, view.output) + "</div>";
            }
            break;
        case HwActionResultView::Phase::RenderedEmpty:
            h += "<span class=\"gp-mute\">" + html_escape(plugin + "." + action) +
                 " completed with no output.</span>";
            break;
        case HwActionResultView::Phase::Failed:
            h += "<div class=\"gp-err\">Failed" +
                 (view.error_detail.empty() ? std::string() : ": " + html_escape(view.error_detail.substr(0, 200))) +
                 "</div>";
            break;
        case HwActionResultView::Phase::TimedOut:
            h += "<span class=\"gp-mute\">Timed out waiting for a response.</span>";
            break;
    }
    h += "</div>";
    return h;
}

} // namespace yuzu::server
