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

std::string url_enc(const std::string& s) {
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

std::string withheld_note(const char* what) {
    return degraded(std::string("<b>") + what +
                    " withheld.</b> The access-audit record for this view could not be written, so "
                    "the data is not shown. Retry shortly.");
}

// total_seconds / 3600 to one decimal, integer arithmetic (rounds half up).
std::string hours_text(std::int64_t seconds) {
    if (seconds < 0)
        seconds = 0;
    const std::int64_t tenths = (seconds * 10 + 1800) / 3600;
    return std::to_string(tenths / 10) + "." + std::to_string(tenths % 10);
}

std::string when_cell(std::int64_t epoch) {
    return epoch > 0 ? "<td class=\"hw-mono\">" + esc(format_iso_utc(epoch)) + "</td>"
                     : "<td><span class=\"hw-grey\">&mdash;</span></td>";
}

std::string text_cell(const std::string& v) {
    return v.empty() ? "<td><span class=\"hw-grey\">&mdash;</span></td>"
                     : "<td>" + esc(v) + "</td>";
}

} // namespace

std::string render_usage_load_hosts(const std::string& agent_id) {
    // hx-trigger="click" on a button: the request, and the audit row it writes, happen
    // only when an operator asks. The result replaces the host's contents.
    auto host = [&](const char* cls, const char* path, const char* label, const char* note) {
        return std::string("<div class=\"hw-panel dd-panel ") + cls + "\" style=\"margin-top:22px\">"
               "<div class=\"hw-hd\"><h2>" + label + "</h2><span class=\"hw-lab\">" + note +
               "</span><div class=\"hw-end\"><button type=\"button\" class=\"gp-btn\" hx-get=\"" +
               path + "?id=" + url_enc(agent_id) +
               "\" hx-trigger=\"click\" hx-target=\"closest .dd-panel\" hx-swap=\"outerHTML\">"
               "Load</button></div></div></div>";
    };
    return host("dd-usage", "/fragments/hardware/ci/app-usage", "Application usage",
                "Loading is recorded in the audit log.") +
           host("dd-licences", "/fragments/hardware/ci/licences", "Detected licences",
                "Loading is recorded in the audit log.");
}

std::string render_app_usage_panel(const AppUsageView& v) {
    std::string h = "<div class=\"hw-panel dd-panel dd-usage\" style=\"margin-top:22px\"" +
                    attr("agent", v.agent_id) + "><div class=\"hw-hd\"><h2>Application usage</h2>"
                    "<span class=\"hw-lab\">Hours, last 30 days. Loading is recorded in the audit "
                    "log.</span></div>";
    if (std::holds_alternative<Denied>(v.body))
        return h + note("Application usage needs the <b>Forensics:Read</b> permission for this "
                        "device.") + "</div>";
    if (std::holds_alternative<Unavailable>(v.body))
        return h + degraded("<b>Application usage could not be read.</b> This is not an empty "
                            "list; retry shortly.") + "</div>";
    if (std::holds_alternative<Withheld>(v.body))
        return h + withheld_note("Application usage") + "</div>";

    const auto& d = std::get<AppUsageData>(v.body);
    if (d.rows.empty())
        return h + note("This device reported no application usage for the retained window.") +
               "</div>";
    std::vector<const AppUsageRow*> order;
    order.reserve(d.rows.size());
    for (const auto& r : d.rows)
        order.push_back(&r);
    std::stable_sort(order.begin(), order.end(), [](const AppUsageRow* a, const AppUsageRow* b) {
        return a->total_seconds_30d > b->total_seconds_30d;
    });
    const std::size_t shown = std::min(order.size(), kAppUsageDisplayCap);
    h += "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr><th>Executable</th>"
         "<th>Hours, last 30 days</th><th>Runs, last 30 days</th><th>First seen</th>"
         "<th>Last seen</th></tr></thead><tbody>";
    for (std::size_t i = 0; i < shown; ++i) {
        const auto& r = *order[i];
        h += "<tr><td class=\"hw-mono\" title=\"" + esc(r.exe_key) + "\">" + esc(r.exe_key) +
             "</td><td class=\"hw-mono\">" + hours_text(r.total_seconds_30d) +
             "</td><td class=\"hw-mono\">" + std::to_string(r.run_count_30d) + "</td>" +
             when_cell(r.first_seen) + when_cell(r.last_seen) + "</tr>";
    }
    h += "</tbody></table></div>";
    if (order.size() > shown)
        h += "<div class=\"hw-page\">Showing " + std::to_string(shown) + " of " +
             std::to_string(order.size()) + " executables, most hours first. A device reports at "
             "most " + std::to_string(kAppUsageStoreCap) + ".</div>";
    h += "<div class=\"hw-page\">Last collected " + esc(format_iso_utc(d.collected_at)) +
         ". First and last seen are within the retained usage window only.</div></div>";
    return h;
}

std::string render_licences_panel(const LicencesView& v) {
    std::string h = "<div class=\"hw-panel dd-panel dd-licences\" style=\"margin-top:22px\"" +
                    attr("agent", v.agent_id) + "><div class=\"hw-hd\"><h2>Detected licences</h2>"
                    "<span class=\"hw-lab\">Loading is recorded in the audit log.</span></div>";
    if (std::holds_alternative<Denied>(v.body))
        return h + note("Detected licences need the <b>SoftwareLicensing:Read</b> permission for "
                        "this device.") + "</div>";
    if (std::holds_alternative<Unavailable>(v.body))
        return h + degraded("<b>Detected licences could not be read.</b> This is not an empty "
                            "list; retry shortly.") + "</div>";
    if (std::holds_alternative<Withheld>(v.body))
        return h + withheld_note("Detected licences") + "</div>";
    const auto& rows = std::get<std::vector<LicenceRow>>(v.body);
    if (rows.empty())
        return h + note("No licences detected on this device.") + "</div>";
    h += "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr><th>Product</th><th>Vendor</th>"
         "<th>Version</th><th>Type</th><th>State</th><th>Channel</th><th>Key hint</th>"
         "<th>Detector</th><th>Expires</th><th>Confidence</th></tr></thead><tbody>";
    for (const auto& r : rows) {
        h += "<tr><td class=\"hw-name\">" + esc(r.product) + "</td>" + text_cell(r.vendor) +
             "<td class=\"hw-mono\">" + esc(r.version) + "</td>" + text_cell(r.license_type) +
             text_cell(r.state) + text_cell(r.channel) + text_cell(r.key_hint) +
             text_cell(r.detector) + when_cell(r.expiry_at) +
             text_cell(r.confidence) + "</tr>";
    }
    h += "</tbody></table></div></div>";
    return h;
}

std::string render_inventory_sources_panel(
    const std::variant<std::vector<SourceRow>, Unavailable, Denied>& v) {
    std::string h = "<div class=\"hw-panel dd-panel\" id=\"dd-sources\" style=\"margin-top:22px\">"
                    "<div class=\"hw-hd\"><h2>Inventory sources</h2><span class=\"hw-lab\">Each "
                    "source is a daily sync from the agents.</span></div>";
    if (std::holds_alternative<Denied>(v))
        return h + note("Needs a fleet-wide <b>Inventory:Read</b> grant.") + "</div>";
    if (std::holds_alternative<Unavailable>(v))
        return h + degraded("<b>Inventory sources could not be read.</b> This is not an empty "
                            "list; retry shortly.") + "</div>";
    const auto& rows = std::get<std::vector<SourceRow>>(v);
    if (rows.empty())
        return h + note("No inventory has been collected yet.") + "</div>";
    h += "<div class=\"hw-scroll\"><table class=\"hw-tbl\"><thead><tr><th>Source</th><th>Devices</th>"
         "<th>Last collected</th></tr></thead><tbody>";
    for (const auto& r : rows)
        h += "<tr><td class=\"hw-name\">" + esc(r.plugin) + "</td><td class=\"hw-mono\">" +
             std::to_string(r.agent_count) + "</td>" + when_cell(r.last_collected) + "</tr>";
    h += "</tbody></table></div></div>";
    return h;
}

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
