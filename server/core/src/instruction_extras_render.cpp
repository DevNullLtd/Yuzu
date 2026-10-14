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

std::string render_instruction_sets_panel(const std::vector<SetRow>& rows, bool counts_partial) {
    std::string h = "<section class=\"panel\" data-panel=\"instruction-sets\"><div class=\"hd\">"
                    "<h2><strong>" +
                    std::to_string(rows.size()) + "</strong> instruction sets</h2></div>";
    if (rows.empty()) {
        h += "<div class=\"empty-state\">No instruction sets yet.</div></section>";
        return h;
    }
    h += "<div class=\"tw\"><table><thead><tr><th>Set</th><th>Description</th>"
         "<th>Definitions</th></tr></thead><tbody>";
    for (const auto& r : rows) {
        h += "<tr data-set-id=\"" + html_escape(r.set.id) + "\"><td><strong>" +
             html_escape(r.set.name) + "</strong><span class=\"sub-id\">" +
             html_escape(r.set.id.substr(0, 8)) + "</span></td><td>" +
             html_escape(r.set.description) + "</td><td>" + std::to_string(r.members) +
             (counts_partial ? "+" : "") + "</td></tr>";
    }
    h += "</tbody></table></div></section>";
    return h;
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
