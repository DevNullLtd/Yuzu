#include "instruction_extras_render.hpp"

#include "web_utils.hpp"

#include <algorithm>
#include <charconv>

namespace yuzu::server::instruction_extras {

int clamp_library_limit(const std::string& raw) {
    int v = 0;
    const auto* b = raw.data();
    const auto* e = b + raw.size();
    auto [p, ec] = std::from_chars(b, e, v);
    if (raw.empty() || ec != std::errc{} || p != e || v <= 0)
        return kLibraryDefaultLimit;
    return std::min(v, kLibraryMaxLimit);
}

InstructionDefinition merge_yaml_into_stored(const InstructionDefinition& stored,
                                             const instruction_yaml::DefinitionFields& f,
                                             const std::string& yaml_source,
                                             const std::string& saved_by) {
    auto pick = [](const std::string& yaml_value, const std::string& stored_value,
                   const char* fallback) {
        if (!yaml_value.empty())
            return yaml_value;
        return stored_value.empty() ? std::string(fallback) : stored_value;
    };

    InstructionDefinition def = stored; // carries every column the YAML cannot express
    def.name = f.name;
    def.plugin = f.plugin;
    def.action = f.action; // lowercased by the parser
    // Keep the stored description when the YAML does not mention one; an explicit
    // `description: ""` still clears it.
    if (f.has_description)
        def.description = f.description;
    def.version = pick(f.version, stored.version, "1.0.0");
    def.type = pick(f.type, stored.type, "question");
    def.concurrency_mode = pick(f.concurrency, stored.concurrency_mode, "per-device");
    def.approval_mode = pick(f.approval, stored.approval_mode, "auto");
    def.yaml_source = yaml_source;
    def.parameter_schema.clear(); // empty means KEEP in update_definition
    if (def.created_by.empty())
        def.created_by = saved_by;
    return def;
}

const char* approval_label(const std::string& m) {
    if (m == "auto")
        return "No";
    if (m == "always")
        return "Yes";
    if (m == "role-gated")
        return "Unless administrator";
    return "Unknown";
}

std::string render_library_foot(int limit, bool truncated) {
    if (!truncated)
        return {};
    return "<div class=\"empty-state\" data-truncated=\"1\">Showing the first " +
           std::to_string(limit) + ". Narrow the filter.</div>";
}

std::string render_instruction_sets_panel(const std::vector<SetRow>& rows, bool counts_partial,
                                          bool can_write, bool can_delete) {
    std::string h = "<section class=\"panel\" data-panel=\"instruction-sets\"><div class=\"hd\">"
                    "<h2><strong>" +
                    std::to_string(rows.size()) + "</strong> instruction sets</h2>";
    if (can_write)
        h += "<div class=\"end\"><button type=\"button\" class=\"btn btn-secondary btn-sm\" "
             "data-ox=\"set-new\">New set</button></div>";
    h += "</div>";
    if (rows.empty()) {
        h += "<div class=\"empty-state\">No instruction sets yet.</div></section>";
        return h;
    }
    h += "<div class=\"tw\"><table><thead><tr><th>Set</th><th>Description</th>"
         "<th>Definitions</th>";
    if (can_delete)
        h += "<th></th>";
    h += "</tr></thead><tbody>";
    for (const auto& r : rows) {
        h += "<tr data-set-id=\"" + html_escape(r.set.id) + "\"><td><strong>" +
             html_escape(r.set.name) + "</strong><span class=\"sub-id\">" +
             html_escape(r.set.id.substr(0, 8)) + "</span></td><td>" +
             html_escape(r.set.description) + "</td><td>" + std::to_string(r.members) +
             (counts_partial ? "+" : "") + "</td>";
        if (can_delete)
            h += "<td class=\"act\"><button type=\"button\" class=\"btn btn-danger btn-sm\" "
                 "data-ox=\"set-delete\" data-set-id=\"" +
                 html_escape(r.set.id) + "\" data-set-name=\"" + html_escape(r.set.name) +
                 "\" data-set-members=\"" + std::to_string(r.members) + "\">Delete</button></td>";
        h += "</tr>";
    }
    h += "</tbody></table></div></section>";
    return h;
}

std::string render_library_filter_form(const std::string& name, const std::string& plugin,
                                       const std::string& type) {
    auto in = [](const char* field, const char* label, const std::string& v) {
        return std::string("<input type=\"text\" name=\"") + field + "\" placeholder=\"" + label +
               "\" aria-label=\"" + label + "\" maxlength=\"128\" value=\"" + html_escape(v) +
               "\">";
    };
    return "<form class=\"ox-filter\" hx-get=\"/fragments/instructions\" "
           "hx-target=\"#tab-definitions\" hx-swap=\"innerHTML\">" +
           in("name", "Name contains", name) + in("plugin", "Plugin", plugin) +
           in("type", "Type", type) +
           "<button type=\"submit\" class=\"btn btn-secondary btn-sm\">Filter</button></form>";
}

std::string render_set_select(const std::string& definition_id, const std::string& current_set_id,
                              const std::vector<InstructionSet>& sets) {
    std::string h = "<select class=\"ox-set\" data-ox=\"set-assign\" data-def-id=\"" +
                    html_escape(definition_id) + "\" data-prev=\"" + html_escape(current_set_id) +
                    "\" aria-label=\"Instruction set\"><option value=\"\"" +
                    std::string(current_set_id.empty() ? " selected" : "") + ">-</option>";
    bool known = current_set_id.empty();
    for (const auto& s : sets) {
        const bool sel = s.id == current_set_id;
        known = known || sel;
        h += "<option value=\"" + html_escape(s.id) + "\"" + (sel ? " selected" : "") + ">" +
             html_escape(s.name) + "</option>";
    }
    // A set id that no longer lists (deleted, or a degraded read) stays visible, never silently
    // reads as unassigned.
    if (!known)
        h += "<option value=\"" + html_escape(current_set_id) + "\" selected>" +
             html_escape(current_set_id.substr(0, 8)) + "</option>";
    return h + "</select>";
}

std::string render_templates_panel(const std::string& definition_id,
                                   const std::string& definition_name,
                                   const std::vector<ResponseTemplate>& templates, bool can_write) {
    ResponseTemplatesEngine engine;
    std::string h = "<section class=\"panel\" data-panel=\"response-templates\" "
                    "data-def-id=\"" +
                    html_escape(definition_id) + "\"><div class=\"hd\"><h2>Response templates: " +
                    html_escape(definition_name) + "</h2>";
    if (can_write)
        h += "<div class=\"end\"><button type=\"button\" class=\"btn btn-secondary btn-sm\" "
             "data-ox=\"tpl-new\" data-def-id=\"" +
             html_escape(definition_id) + "\">New template</button></div>";
    h += "</div><div class=\"tw\"><table><thead><tr><th>Name</th><th>Columns</th><th>Sort</th>"
         "<th>Filters</th><th></th></tr></thead><tbody>";
    // The synthesised default: fixed, no actions. An authored default hides it in the API list;
    // here it is always named so the fallback is never a surprise.
    h += "<tr data-tpl-id=\"__default__\"><td><strong>Default (built in)</strong></td>"
         "<td colspan=\"3\">All columns</td><td></td></tr>";
    for (const auto& t : templates) {
        h += "<tr data-tpl-id=\"" + html_escape(t.id) + "\"><td><strong>" + html_escape(t.name) +
             "</strong>" + (t.is_default ? " <span class=\"legacy-badge\">default</span>" : "") +
             "</td><td>" +
             (t.columns.empty() ? std::string("All") : std::to_string(t.columns.size())) +
             "</td><td>" +
             (t.sort_column.empty()
                  ? std::string("-")
                  : html_escape(t.sort_column) + " " + html_escape(t.sort_dir.empty() ? "asc" : t.sort_dir)) +
             "</td><td>" + std::to_string(t.filters.size()) + "</td><td class=\"act\">";
        if (can_write) {
            h += "<button type=\"button\" class=\"btn btn-secondary btn-sm\" data-ox=\"tpl-edit\" "
                 "data-def-id=\"" +
                 html_escape(definition_id) + "\" data-tpl-id=\"" + html_escape(t.id) +
                 "\" data-tpl=\"" + html_escape(engine.to_json(t).dump()) +
                 "\">Edit</button> <button type=\"button\" class=\"btn btn-danger btn-sm\" "
                 "data-ox=\"tpl-delete\" data-def-id=\"" +
                 html_escape(definition_id) + "\" data-tpl-id=\"" + html_escape(t.id) +
                 "\" data-tpl-name=\"" + html_escape(t.name) + "\">Delete</button>";
        }
        h += "</td></tr>";
    }
    h += "</tbody></table></div><p class=\"hint ox-pad\">The Console uses the first enabled "
         "definition with the same plugin and action, by name, to pick its template.</p></section>";
    return h;
}

std::string render_templates_denied() {
    return "<section class=\"panel\" data-panel=\"response-templates\"><div class=\"empty-state\" "
           "data-denied=\"true\">Viewing response templates needs the instruction definition "
           "read permission.</div></section>";
}

std::string render_templates_degraded() {
    return "<section class=\"panel\" data-panel=\"response-templates\"><div class=\"empty-state\" "
           "data-degraded=\"1\">Response templates unavailable. This is not an empty list."
           "</div></section>";
}

std::string render_templates_not_found() {
    return "<section class=\"panel\" data-panel=\"response-templates\"><div class=\"empty-state\">"
           "That definition was not found.</div></section>";
}

std::string render_sets_denied() {
    return "<section class=\"panel\" data-panel=\"instruction-sets\"><div class=\"empty-state\" "
           "data-denied=\"true\">Viewing instruction sets needs the instruction set read "
           "permission.</div></section>";
}

std::string render_sets_degraded() {
    return "<section class=\"panel\" data-panel=\"instruction-sets\"><div class=\"empty-state\" "
           "data-degraded=\"1\">Instruction sets unavailable. This is not an empty list."
           "</div></section>";
}

std::string render_library_degraded() {
    return "<div class=\"empty-state\" data-degraded=\"1\">Instruction store unavailable. "
           "This is not an empty library.</div>";
}

} // namespace yuzu::server::instruction_extras
