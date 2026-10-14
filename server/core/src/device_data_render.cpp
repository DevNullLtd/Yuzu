#include "device_data_render.hpp"

#include "web_utils.hpp" // html_escape, format_iso_utc

#include <algorithm>
#include <unordered_map>

namespace yuzu::server::device_data {

namespace {

std::string esc(const std::string& s) {
    return html_escape(s);
}

std::string note(const std::string& html) {
    return "<div class=\"hw-empty\">" + html + "</div>";
}

std::string degraded(const std::string& html) {
    return "<div class=\"gp-banner hw-degrade\">" + html + "</div>";
}

std::string type_pill(const std::string& type) {
    return "<span class=\"hw-pill\">" + esc(type.empty() ? "string" : type) + "</span>";
}

// One button. Every control is a `data-act`; the delegated listener in
// static/yuzu-device-data.js reads the data-* attributes, so nothing here is
// executable markup and every value is attribute-escaped.
std::string act_button(const char* act, const std::string& label, const std::string& attrs,
                       bool danger = false) {
    return std::string("<button type=\"button\" class=\"gp-btn") + (danger ? " danger" : "") +
           "\" data-act=\"" + act + "\"" + attrs + ">" + label + "</button>";
}

std::string attr(const char* name, const std::string& value) {
    return std::string(" data-") + name + "=\"" + esc(value) + "\"";
}

std::string properties_body(const PropertiesView& v,
                            const std::unordered_map<std::string, const SchemaRow*>& schema_by_key) {
    if (std::holds_alternative<Denied>(v.properties))
        return note("Custom properties need the <b>Infrastructure:Read</b> permission for this "
                    "device.");
    if (std::holds_alternative<Unavailable>(v.properties))
        return degraded("<b>Custom properties could not be read.</b> The property store is "
                        "degraded. This is not an empty list; retry shortly.");
    const auto& rows = std::get<std::vector<PropertyRow>>(v.properties);
    if (rows.empty())
        return note("No properties set.");
    std::string h = "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr><th>Property</th>"
                    "<th>Value</th><th>Type</th><th>Schema</th><th>Updated</th>";
    if (v.can_write_properties)
        h += "<th></th>";
    h += "</tr></thead><tbody>";
    for (const auto& p : rows) {
        const auto it = schema_by_key.find(p.key);
        const SchemaRow* schema = it == schema_by_key.end() ? nullptr : it->second;
        h += "<tr><td class=\"hw-name\">" + esc(p.key) + "</td><td class=\"hw-mono\" title=\"" +
             esc(p.value) + "\">" + esc(p.value) + "</td><td>" + type_pill(p.type) + "</td><td>";
        h += schema ? esc(schema->display_name.empty() ? schema->key : schema->display_name)
                    : "<span class=\"hw-grey\">&mdash;</span>";
        h += "</td><td class=\"hw-mono\">" + esc(format_iso_utc(p.updated_at)) + "</td>";
        if (v.can_write_properties) {
            // The schema's type (when one exists) fixes the property type, so the
            // edit form only offers a type field when none does.
            const std::string common = attr("agent", v.agent_id) + attr("key", p.key);
            h += "<td>" +
                 act_button("prop-set", "Edit",
                            common + attr("value", p.value) + attr("type", p.type) +
                                attr("schema-type", schema ? schema->type : "")) +
                 " " + act_button("prop-delete", "Delete", common, /*danger=*/true) + "</td>";
        }
        h += "</tr>";
    }
    h += "</tbody></table></div>";
    return h;
}

std::string schemas_body(const PropertiesView& v) {
    if (std::holds_alternative<Denied>(v.schemas))
        return note("Property schemas need a fleet-wide <b>Infrastructure:Read</b> grant.");
    if (std::holds_alternative<Unavailable>(v.schemas))
        return degraded("<b>Property schemas could not be read.</b> This is not an empty list; "
                        "retry shortly.");
    const auto& rows = std::get<std::vector<SchemaRow>>(v.schemas);
    if (rows.empty())
        return note("No schemas defined.");
    std::string h = "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr><th>Key</th>"
                    "<th>Display name</th><th>Type</th><th>Validation</th><th>Description</th>"
                    "</tr></thead><tbody>";
    for (const auto& s : rows) {
        h += "<tr" + attr("schema-key", s.key) + "><td class=\"hw-name\">" + esc(s.key) +
             "</td><td>" + esc(s.display_name) +
             "</td><td>" + type_pill(s.type) + "</td><td class=\"hw-mono\">";
        h += s.validation_regex.empty() ? "<span class=\"hw-grey\">&mdash;</span>"
                                        : esc(s.validation_regex);
        h += "</td><td>" + esc(s.description) + "</td></tr>";
    }
    h += "</tbody></table></div>";
    return h;
}

} // namespace

std::string render_properties_panels(const PropertiesView& v) {
    // Schemas are only used to label property rows; a denied or degraded schema
    // read simply leaves the Schema column blank.
    std::unordered_map<std::string, const SchemaRow*> schema_by_key;
    if (const auto* rows = std::get_if<std::vector<SchemaRow>>(&v.schemas))
        for (const auto& s : *rows)
            schema_by_key.emplace(s.key, &s);

    std::string h = "<div class=\"hw-panel dd-panel\" id=\"dd-props\"" + attr("agent", v.agent_id) +
                    "><div class=\"hw-hd\"><h2>Custom properties</h2>";
    h += "<span class=\"hw-lab\">Used by scope expressions as props.&lt;key&gt;. Values are "
         "written to the audit log.</span>";
    if (v.can_write_properties &&
        !std::holds_alternative<Unavailable>(v.properties) &&
        !std::holds_alternative<Denied>(v.properties))
        h += "<div class=\"hw-end\">" +
             act_button("prop-add", "Add property", attr("agent", v.agent_id)) + "</div>";
    h += "</div>" + properties_body(v, schema_by_key) + "</div>";

    h += "<div class=\"hw-panel dd-panel\" id=\"dd-schemas\" style=\"margin-top:22px\">"
         "<div class=\"hw-hd\"><h2>Property schemas</h2>"
         "<span class=\"hw-lab\">Schemas apply to every device.</span>";
    if (v.can_write_schemas && std::holds_alternative<std::vector<SchemaRow>>(v.schemas))
        h += "<div class=\"hw-end\">" + act_button("schema-save", "Save schema", "") + "</div>";
    h += "</div>" + schemas_body(v) + "</div>";
    return h;
}

} // namespace yuzu::server::device_data
