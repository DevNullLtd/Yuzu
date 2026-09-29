/// @file guardian_form_render.cpp — see guardian_form_render.hpp.

#include "guardian_form_render.hpp"

#include "guardian_schema_registry.hpp"
#include "web_utils.hpp"

#include <cctype>

namespace yuzu::server::guardian {

namespace {

using nlohmann::json;

// The published schema catalog, parsed once. We deliberately re-parse the
// serialised string (the same artefact GET /schemas serves) rather than reach
// into the registry's json builder — the form is just another catalog consumer,
// and the registry's TU keeps its "string-only past this boundary" contract.
const json& form_catalog() {
    static const json c = [] {
        auto parsed = json::parse(guardian_schema_catalog().json, nullptr, /*allow_exceptions=*/false);
        return parsed.is_discarded() ? json::object() : parsed;
    }();
    return c;
}

// The catalog's `schemas` array, returned by reference into the long-lived static.
// Callers MUST iterate this (not `form_catalog().value("schemas", ...)`, which
// returns a temporary copy) when they keep a pointer/reference to an element past
// the loop — a `&element` into the copy would dangle (it did: assemble caught a
// type_error.306 reading the freed entry).
const json& catalog_schemas() {
    static const json empty = json::array();
    const json& c = form_catalog();
    auto it = c.find("schemas");
    return (it != c.end() && it->is_array()) ? *it : empty;
}

// "value_name" / "expected-hash" → "Value name" / "Expected hash".
std::string humanize(const std::string& key) {
    std::string s = key;
    for (auto& c : s)
        if (c == '_' || c == '-') c = ' ';
    if (!s.empty()) s[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(s[0])));
    return s;
}

// A JSON-Schema property whose type is "integer" or includes "integer" (the
// lenient ["integer","string"] form the numeric params use). Enums are excluded
// by the caller — a short enum belongs inline, not in the Advanced bucket.
bool prop_is_integer(const json& prop) {
    if (!prop.contains("type")) return false;
    const auto& t = prop["type"];
    if (t.is_string()) return t.get<std::string>() == "integer";
    if (t.is_array())
        for (const auto& e : t)
            if (e.is_string() && e.get<std::string>() == "integer") return true;
    return false;
}

// Curated, jargon-free label for a trigger (= assertion type). "" → caller falls
// back to the catalog title, so a future type is still selectable before it is
// relabelled here.
std::string curated_trigger_label(const std::string& assertion_type) {
    if (assertion_type == "registry-value-equals") return "Registry value change";
    if (assertion_type == "file-exists") return "File created / deleted";
    if (assertion_type == "file-hash-equals") return "File content change";
    return "";
}

// One labelled control rendered from a param's JSON-Schema property. enum→select,
// integer→number, else text; honours default (as placeholder), minimum, required,
// and surfaces the schema description as an inline hint (self-documenting form).
std::string render_param_field(const std::string& type_ns, const std::string& key,
                               const json& prop, bool required) {
    const std::string name = form_field_name(type_ns, key);
    const std::string ename = html_escape(name);
    std::string h = "<div class=\"gs-field\"><label for=\"" + ename + "\">" +
                    html_escape(humanize(key)) + (required ? " *" : "") + "</label>";

    if (prop.contains("enum") && prop["enum"].is_array()) {
        const std::string dflt = prop.value("default", std::string{});
        h += "<select id=\"" + ename + "\" name=\"" + ename + "\">";
        for (const auto& opt : prop["enum"]) {
            const std::string v = opt.is_string() ? opt.get<std::string>() : opt.dump();
            h += "<option value=\"" + html_escape(v) + "\"" + (v == dflt ? " selected" : "") + ">" +
                 html_escape(v) + "</option>";
        }
        h += "</select>";
    } else {
        const bool is_int = prop_is_integer(prop);
        std::string placeholder;
        if (prop.contains("default")) {
            const auto& d = prop["default"];
            if (d.is_string())
                placeholder = d.get<std::string>();
            else if (d.is_number_integer())
                placeholder = std::to_string(d.get<long long>());
            else if (d.is_number_unsigned())
                placeholder = std::to_string(d.get<unsigned long long>());
        }
        h += "<input id=\"" + ename + "\" name=\"" + ename + "\"";
        h += is_int ? " type=\"number\"" : " type=\"text\"";
        if (is_int && prop.contains("minimum") && prop["minimum"].is_number_integer())
            h += " min=\"" + std::to_string(prop["minimum"].get<long long>()) + "\"";
        if (is_int && prop.contains("maximum") && prop["maximum"].is_number_integer())
            h += " max=\"" + std::to_string(prop["maximum"].get<long long>()) + "\"";
        if (!placeholder.empty())
            h += " placeholder=\"" + html_escape(placeholder) + "\"";
        if (required)
            h += " required";
        h += ">";
    }

    if (const std::string desc = prop.value("description", std::string{}); !desc.empty())
        h += "<div class=\"gs-hint\">" + html_escape(desc) + "</div>";
    h += "</div>";
    return h;
}

// The per-trigger param fieldset. Disabled+hidden for all but the first option, so
// (a) only the active trigger's fields submit and its required fields validate,
// and (b) same-named params across triggers never collide (belt to the
// namespacing braces). Integer params are tucked under a per-trigger "Advanced".
std::string render_trigger_fieldset(const std::string& type, const json& entry, bool first) {
    const json params = entry.value("json_schema", json::object()).value("properties", json::object())
                            .value("params", json::object());
    const json& props = params.contains("properties") ? params["properties"] : json::object();
    const json required = params.value("required", json::array());
    auto is_required = [&](const std::string& k) {
        for (const auto& r : required)
            if (r.is_string() && r.get<std::string>() == k) return true;
        return false;
    };

    std::string core, adv;
    for (auto it = props.begin(); it != props.end(); ++it) {
        const std::string field = render_param_field(type, it.key(), it.value(), is_required(it.key()));
        const bool advanced = prop_is_integer(it.value()) && !it.value().contains("enum");
        (advanced ? adv : core) += field;
    }

    std::string h = "<fieldset class=\"gs-trigger-fields\" data-trigger=\"" + html_escape(type) + "\"";
    if (!first) h += " hidden disabled";
    h += ">" + core;
    if (!adv.empty())
        h += "<details class=\"gs-advanced\"><summary>Advanced</summary>" + adv + "</details>";
    h += "</fieldset>";
    return h;
}

// A single resilience-policy numeric field. `modes` is the space-separated set the
// param is load-bearing for (mirrors the schema's x-applies-to-modes); the field
// is hidden unless the initial mode (persist) is in that set — guardianPickResilienceMode
// re-applies on change so only mode-relevant knobs ever show.
std::string res_field(const char* name, const char* label, const char* minv, const char* placeholder,
                      const char* modes) {
    const std::string m = modes;
    const bool show = m.find("persist") != std::string::npos;
    std::string h = "<div class=\"gs-field gs-res-field\" data-modes=\"" + m + "\"";
    if (!show) h += " hidden";
    h += "><label>" + std::string(label) + "</label><input type=\"number\" name=\"" + name +
         "\" min=\"" + minv + "\" placeholder=\"" + placeholder + "\"></div>";
    return h;
}

} // namespace

std::string form_field_name(const std::string& assertion_type, const std::string& param_key) {
    return assertion_type + "__" + param_key;
}

std::string render_guard_form(const std::string& error_html) {
    std::string h =
        "<div class=\"gs-modal-card\">"
        "<form class=\"gs-form\" hx-post=\"/fragments/guardian/guards\" "
        "hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">"
        "<div class=\"gs-modal-header\"><h3>New Guard</h3>"
        "<button type=\"button\" class=\"gs-modal-close\" onclick=\"guardianCloseModal()\" "
        "aria-label=\"Close\">&times;</button></div>"
        "<div class=\"gs-modal-body\">";
    if (!error_html.empty())
        h += error_html;
    h += "<label>Name</label><input name=\"name\" placeholder=\"block-smb-445\" required>"
         "<div class=\"form-row\">"
         "<div><label>Severity</label><select name=\"severity\">"
         "<option>critical</option><option selected>high</option><option>medium</option>"
         "<option>low</option></select></div>"
         "<div><label>Mode</label><select name=\"mode\" onchange=\"guardianPickMode(this)\">"
         "<option value=\"watch\" selected>Observe &mdash; detect &amp; alert</option>"
         "<option value=\"enforce\">Enforce &mdash; auto-remediate</option></select></div></div>"
         "<label>Trigger type</label>"
         "<select name=\"trigger_type\" onchange=\"guardianPickTrigger(this)\">";

    // Trigger options + their param fieldsets, both from the schema catalog.
    std::string fieldsets;
    bool first = true;
    for (const auto& e : catalog_schemas()) {
        if (e.value("kind", std::string{}) != "assertion") continue;
        const std::string type = e.value("type", std::string{});
        std::string label = curated_trigger_label(type);
        if (label.empty())
            label = e.value("json_schema", json::object()).value("title", type);
        h += "<option value=\"" + html_escape(type) + "\">" + html_escape(label) + "</option>";
        fieldsets += render_trigger_fieldset(type, e, first);
        first = false;
    }
    h += "</select>";
    h += fieldsets;

    // Remediation only applies in Enforce mode. guardianPickMode reveals this block
    // when Mode = Enforce; it stays hidden for Watch (observe & alert only).
    h += "<div class=\"gs-enforce-only\" hidden>"
         "<div class=\"gs-hint\" style=\"margin-bottom:0.4rem\">When drift is detected, Guardian "
         "writes the expected state back. Tune how persistently it re-enforces below.</div>"
         "<details class=\"gs-advanced gs-resilience\"><summary>Resilience policy (advanced)</summary>"
         "<div class=\"gs-hint\">Governs re-enforcement when a target keeps drifting (enforce only). "
         "Only the fields relevant to the chosen mode are shown.</div>"
         "<label>Mode</label>"
         "<select name=\"resilience_mode\" onchange=\"guardianPickResilienceMode(this)\">"
         "<option value=\"persist\" selected>persist &mdash; fix on every drift, never give up</option>"
         "<option value=\"backoff\">backoff &mdash; exponential delay, never give up</option>"
         "<option value=\"bounded\">bounded &mdash; give up after N cycles</option></select>";
    h += res_field("max_attempts", "Max attempts", "1", "5", "bounded");
    h += res_field("quiet_reset_s", "Quiet reset (s)", "1", "60", "backoff bounded");
    h += res_field("resume_after_s", "Resume after (s)", "0", "0 = stay given up", "bounded");
    h += res_field("backoff_initial_ms", "Backoff initial (ms)", "1", "1000", "backoff");
    h += res_field("backoff_max_ms", "Backoff max (ms)", "1", "60000", "backoff");
    h += res_field("event_debounce_ms", "Event debounce (ms)", "0", "1000", "persist backoff bounded");
    h += "</details></div>"; // close gs-resilience details + gs-enforce-only wrapper

    h += "</div>" // gs-modal-body
         "<div class=\"gs-modal-footer\">"
         "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">"
         "Cancel</button>"
         "<button type=\"submit\" class=\"btn btn-secondary\">Create Guard</button></div>"
         "</form></div>";
    return h;
}

std::string render_baseline_form(const std::vector<std::string>& guard_names,
                                 const BaselineFormEdit& edit) {
    const bool editing = !edit.baseline_id.empty();

    // Member-guards datalist: native type-to-filter dropdown of existing guards.
    std::string datalist;
    for (const auto& n : guard_names)
        datalist += "<option value=\"" + html_escape(n) + "\">";

    // In edit mode, pre-render the current members as removable chips matching the
    // structure guardianAddGuardChip() builds client-side (hidden name="guards"
    // input + label + remove button), so they submit and de-dupe identically.
    std::string chips;
    for (const auto& n : edit.selected) {
        const std::string e = html_escape(n);
        chips += "<span class=\"bl-chip\"><input type=\"hidden\" name=\"guards\" value=\"" + e +
                 "\">" + e +
                 " <button type=\"button\" class=\"bl-chip-x\" "
                 "onclick=\"this.closest('.bl-chip').remove()\">&times;</button></span>";
    }

    const std::string action =
        editing ? ("/fragments/guardian/baseline/" + html_escape(edit.baseline_id))
                : std::string("/fragments/guardian/baselines");
    const std::string title = editing ? "Edit Baseline" : "New Baseline";
    const std::string submit = editing ? "Save changes" : "Create Baseline (draft)";
    const std::string name_val = editing ? (" value=\"" + html_escape(edit.name) + "\"") : "";

    std::string h =
        "<div class=\"gs-modal-card\">"
        "<form class=\"gs-form\" hx-post=\"" + action + "\" "
        "hx-target=\"#guardian-modal-content\" hx-swap=\"innerHTML\">"
        "<div class=\"gs-modal-header\"><h3>" + title + "</h3>"
        "<button type=\"button\" class=\"gs-modal-close\" onclick=\"guardianCloseModal()\" "
        "aria-label=\"Close\">&times;</button></div>"
        "<div class=\"gs-modal-body\">"
        "<label>Name</label><input name=\"name\" placeholder=\"CIS Windows L1\"" + name_val +
        " required>"
        "<div class=\"gs-hint\">Device targeting (included / excluded management groups) and deploy "
        "are set from the Baseline's detail panel.</div>"
        "<label>Member Guards</label>"
        "<div class=\"bl-guard-picker\">"
        "<input id=\"bl-guard-input\" list=\"bl-guard-datalist\" autocomplete=\"off\" "
        "placeholder=\"type to search Guards&hellip;\" "
        "onkeydown=\"if(event.key==='Enter'){event.preventDefault();guardianAddGuardChip();}\">"
        "<datalist id=\"bl-guard-datalist\">" + datalist + "</datalist>"
        "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianAddGuardChip()\">"
        "Add</button></div>"
        "<div id=\"bl-selected-guards\" class=\"bl-chips\">" + chips + "</div>"
        "<div class=\"gs-hint\">" +
        std::string(guard_names.empty()
                        ? "No Guards defined yet &mdash; create Guards first, then add them here."
                        : "Pick from existing Guards; the dropdown filters as you type.") +
        "</div>"
        "</div>"
        "<div class=\"gs-modal-footer\">"
        "<button type=\"button\" class=\"btn btn-secondary\" onclick=\"guardianCloseModal()\">"
        "Cancel</button>"
        "<button type=\"submit\" class=\"btn btn-secondary\">" + submit + "</button></div>"
        "</form></div>";
    return h;
}

SparkAssertion assemble_spark_assertion(const std::string& assertion_type,
                                        const std::function<std::string(const std::string&)>& get) {
    SparkAssertion sa;

    // Locate the chosen trigger's assertion schema in the catalog. Iterate the
    // stable reference — a `&e` into a temporary copy would dangle past the loop.
    const json* entry = nullptr;
    for (const auto& e : catalog_schemas())
        if (e.value("kind", std::string{}) == "assertion" &&
            e.value("type", std::string{}) == assertion_type) {
            entry = &e;
            break;
        }
    if (!entry) {
        sa.error = "Unknown trigger type: " + assertion_type;
        return sa;
    }

    const json params = entry->value("json_schema", json::object()).value("properties", json::object())
                            .value("params", json::object());
    const json& props = params.contains("properties") ? params["properties"] : json::object();
    const json required = params.value("required", json::array());

    // Required keys first — a clear, named error beats a downstream empty-field reject.
    for (const auto& rk : required) {
        if (!rk.is_string()) continue;
        const std::string k = rk.get<std::string>();
        if (get(form_field_name(assertion_type, k)).empty()) {
            sa.error = humanize(k) + " is required for this trigger type.";
            return sa;
        }
    }

    // Gather the type's params; omit empty optionals so downstream defaults apply
    // (the agent reads max_bytes/settle_ms/expected_hash with a default when absent).
    json out_params = json::object();
    for (auto it = props.begin(); it != props.end(); ++it) {
        const std::string v = get(form_field_name(assertion_type, it.key()));
        if (!v.empty())
            out_params[it.key()] = v;
    }

    // Spark is implied by the assertion family (registry-* → registry-change,
    // file-* → file-change); its target is taken from the assertion params, so it
    // carries none of its own. Verify the paired spark exists in the catalog.
    const std::string family = assertion_type.substr(0, assertion_type.find('-'));
    const std::string spark_type = family + "-change";
    bool spark_ok = false;
    for (const auto& e : catalog_schemas())
        if (e.value("kind", std::string{}) == "spark" && e.value("type", std::string{}) == spark_type) {
            spark_ok = true;
            break;
        }
    if (!spark_ok) {
        sa.error = "No trigger (spark) is defined for " + assertion_type + ".";
        return sa;
    }

    sa.spark = json{{"type", spark_type}, {"params", json::object()}};
    sa.assertion = json{{"type", assertion_type}, {"params", std::move(out_params)}};
    return sa;
}

} // namespace yuzu::server::guardian
