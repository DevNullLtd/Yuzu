#pragma once

/// @file hardware_action_form.hpp
/// PURE JSON-Schema-subset -> HTML-form-field spec for the Hardware CI record's
/// Actions lens (the generic action runner). No httplib — parses a
/// `parameter_schema` string (an `InstructionDefinition`'s JSON-Schema-shaped
/// column, `instruction_store.hpp`) into a small, renderer-friendly field list.
/// Deliberately narrow: this is a v0 "make every action clickable" form, not a
/// general JSON-Schema form generator — object/array/anyOf properties fall back
/// to a plain text input rather than growing this parser to handle them.

#include "sensitive_instruction_params.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

struct ActionFormField {
    std::string name;
    enum class Kind { Text, Integer, Number, Boolean, Enum } kind{Kind::Text};
    std::vector<std::string> enum_values;
    std::string description;
    std::string default_value; // stringified; "" = no default
    bool required{false};
    bool sensitive{false};
};

/// One documented input from the plugin-docs manifest (`inputs[]`, generated from
/// the definition YAML's `spec.parameters`) — the "syntax guide" shown beside
/// every action form, whether or not a store schema produced typed fields.
struct HintInput {
    std::string name;
    std::string type;
    bool required{false};
    std::string default_value; // "" = none
    std::string constraints;   // compact rendering of the YAML `validation` object, "" = none
    std::string description;
};

struct ActionFormSpec {
    std::vector<ActionFormField> fields;
    bool schema_usable{false}; // false => render a free-form key=value textarea instead
    std::vector<HintInput> inputs; // manifest-documented inputs (may be empty)
    std::string example;           // a captured `key=value ...` invocation, "" = none
    bool manifest_known{false};    // the plugin has a manifest at all
};

/// Fold the plugin-docs manifest's knowledge of ONE action into `spec`:
///   * `inputs[]` rows whose `definition_id` is listed in this action's
///     `actions[].definition_ids` become `spec.inputs`;
///   * when the store schema produced no fields (`!schema_usable`) but the
///     manifest documents inputs, those inputs ALSO become typed form fields
///     (the manifest is generated from the same definition YAML — it just also
///     covers definitions that are disabled or absent from this deployment's
///     store);
///   * `samples[<os>].actions[].params` (falling back to any OS) becomes
///     `spec.example` — the captured `key=value` string that is the best
///     "what do I type here" hint for a definition-less action.
/// `manifest_json` is the pre-serialised manifest (`plugin_docs_manifest(name)->json`);
/// malformed input leaves `spec` untouched. `os` is the agent's reported OS
/// ("darwin" is mapped to the manifest's "macos" key).
inline void apply_manifest_hints(ActionFormSpec& spec, std::string_view manifest_json,
                                 std::string_view action, std::string_view os) {
    auto m = nlohmann::json::parse(manifest_json, nullptr, false);
    if (m.is_discarded() || !m.is_object())
        return;
    spec.manifest_known = true;

    std::vector<std::string> def_ids;
    if (auto acts = m.find("actions"); acts != m.end() && acts->is_array())
        for (const auto& a : *acts)
            if (a.is_object() && a.value("action", "") == action)
                if (auto ids = a.find("definition_ids"); ids != a.end() && ids->is_array())
                    for (const auto& id : *ids)
                        if (id.is_string())
                            def_ids.push_back(id.get<std::string>());

    if (!def_ids.empty())
        if (auto inputs = m.find("inputs"); inputs != m.end() && inputs->is_array())
            for (const auto& in : *inputs) {
                if (!in.is_object())
                    continue;
                const std::string did = in.value("definition_id", "");
                if (std::find(def_ids.begin(), def_ids.end(), did) == def_ids.end())
                    continue;
                HintInput h;
                h.name = in.value("name", "");
                if (h.name.empty())
                    continue;
                h.type = in.value("type", "");
                h.required = in.value("required", false);
                if (auto d = in.find("default"); d != in.end() && !d->is_null())
                    h.default_value = d->is_string() ? d->get<std::string>() : d->dump();
                if (auto c = in.find("constraints"); c != in.end() && c->is_object() && !c->empty())
                    h.constraints = c->dump();
                h.description = in.value("description", "");
                while (!h.description.empty() && (h.description.back() == '\n' || h.description.back() == ' '))
                    h.description.pop_back();
                // Deduplicate by name across a definition family (same action, N definitions).
                bool dup = false;
                for (const auto& e : spec.inputs)
                    if (e.name == h.name) { dup = true; break; }
                if (!dup)
                    spec.inputs.push_back(std::move(h));
            }

    if (!spec.schema_usable && !spec.inputs.empty()) {
        for (const auto& h : spec.inputs) {
            ActionFormField f;
            f.name = h.name;
            f.required = h.required;
            f.sensitive = is_redacted_instruction_param_key(h.name);
            f.description = h.description;
            f.default_value = h.default_value;
            if (h.type == "int32" || h.type == "int64" || h.type == "integer")
                f.kind = ActionFormField::Kind::Integer;
            else if (h.type == "number" || h.type == "double" || h.type == "float")
                f.kind = ActionFormField::Kind::Number;
            else if (h.type == "bool" || h.type == "boolean")
                f.kind = ActionFormField::Kind::Boolean;
            else
                f.kind = ActionFormField::Kind::Text;
            spec.fields.push_back(std::move(f));
        }
        spec.schema_usable = true;
    }

    // Example: prefer the agent's OS, then any OS that captured this action.
    std::string os_key(os);
    if (os_key == "darwin" || os_key == "mac") os_key = "macos";
    if (os_key == "win") os_key = "windows";
    if (os_key == "lin") os_key = "linux";
    auto find_example = [&](const nlohmann::json& per_os) -> std::string {
        if (!per_os.is_object())
            return "";
        auto acts = per_os.find("actions");
        if (acts == per_os.end() || !acts->is_array())
            return "";
        for (const auto& a : *acts)
            if (a.is_object() && a.value("action", "") == action) {
                if (auto pr = a.find("params"); pr != a.end() && pr->is_string())
                    return pr->get<std::string>();
                return "";
            }
        return "";
    };
    if (auto samples = m.find("samples"); samples != m.end() && samples->is_object()) {
        if (auto mine = samples->find(os_key); mine != samples->end())
            spec.example = find_example(*mine);
        if (spec.example.empty())
            for (auto it = samples->begin(); it != samples->end() && spec.example.empty(); ++it)
                spec.example = find_example(it.value());
    }
}

/// `schema_json` is an `InstructionDefinition::parameter_schema` value (may be
/// empty, malformed, or a non-object schema — all three degrade to
/// `schema_usable=false` rather than throwing).
[[nodiscard]] inline ActionFormSpec parse_action_form_spec(std::string_view schema_json) {
    ActionFormSpec spec;
    if (schema_json.empty())
        return spec;
    auto parsed = nlohmann::json::parse(schema_json, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object())
        return spec;
    auto props_it = parsed.find("properties");
    if (props_it == parsed.end() || !props_it->is_object())
        return spec;

    std::vector<std::string> required;
    if (auto req_it = parsed.find("required"); req_it != parsed.end() && req_it->is_array())
        for (const auto& r : *req_it)
            if (r.is_string())
                required.push_back(r.get<std::string>());

    for (auto it = props_it->begin(); it != props_it->end(); ++it) {
        const std::string& name = it.key();
        const nlohmann::json& p = it.value();
        if (!p.is_object())
            continue;
        ActionFormField f;
        f.name = name;
        f.required = std::find(required.begin(), required.end(), name) != required.end();
        f.sensitive = is_redacted_instruction_param_key(name);
        if (auto d = p.find("description"); d != p.end() && d->is_string())
            f.description = d->get<std::string>();

        if (auto e = p.find("enum"); e != p.end() && e->is_array() && !e->empty()) {
            f.kind = ActionFormField::Kind::Enum;
            for (const auto& v : *e)
                if (v.is_string())
                    f.enum_values.push_back(v.get<std::string>());
                else if (!v.is_null())
                    f.enum_values.push_back(v.dump());
        } else {
            std::string type;
            if (auto t = p.find("type"); t != p.end() && t->is_string())
                type = t->get<std::string>();
            if (type == "integer") f.kind = ActionFormField::Kind::Integer;
            else if (type == "number") f.kind = ActionFormField::Kind::Number;
            else if (type == "boolean") f.kind = ActionFormField::Kind::Boolean;
            else f.kind = ActionFormField::Kind::Text; // string, object, array, or unspecified
        }

        if (auto d = p.find("default"); d != p.end() && !d->is_null()) {
            f.default_value = d->is_string() ? d->get<std::string>() : d->dump();
        }
        spec.fields.push_back(std::move(f));
    }
    spec.schema_usable = !spec.fields.empty();
    return spec;
}

} // namespace yuzu::server
