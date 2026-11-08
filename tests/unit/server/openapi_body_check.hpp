#pragma once

/**
 * openapi_body_check.hpp - a value-level check of a REAL response body against the schema the
 * served OpenAPI document declares for it (#6500 item 7, related #6393).
 *
 * The ResponsePin table in test_openapi_spec_completeness.cpp compares the schema's key set to a
 * key list read from the handler; it never looks at a real body and never at a value's type. This
 * header closes that: a route test dispatches the real handler, parses the body it got, and hands
 * it here together with the schema taken from openapi_spec_json().
 *
 * What is checked, recursively, at every level the schema describes:
 *   - `type` (OpenAPI 3.0 spelling, one name: an array `type` throws nlohmann::type_error rather than being
 *     reported as a violation): string, integer (a JSON integer:
 *     5.0 is a float and fails), number (any), boolean, object, array; `nullable: true` admits
 *     null.
 *   - `enum`, `minimum`, `maximum`, `minLength`, `maxLength`, `minItems`, `maxItems`. Lengths are
 *     counted in bytes, not code points.
 *   - every `required` member is present.
 *   - no undeclared member: an object schema that declares `properties` is CLOSED unless it says
 *     `additionalProperties: true` (or gives a schema, which each extra member must satisfy).
 *     An object schema with neither `properties` nor `additionalProperties` is a free-form
 *     object and passes any members; callers that care pin those members themselves.
 *   - `$ref` (local, "#/components/..."), `allOf` (every part), `oneOf` / `anyOf` (at least one).
 *   - `items` for every array element.
 * Any schema keyword it does not model and that could constrain a value (`not`, `if`,
 * `patternProperties`, ...) is itself a violation, so a schema edit that outgrows this checker
 * fails loudly instead of being silently skipped. The exception is a closed list of annotation
 * keywords (`description`, `default`, `example(s)`, `title`, `readOnly`, `writeOnly`,
 * `deprecated`, `externalDocs`, `x-*`) plus three that DO constrain a value but are accepted
 * without being checked: `pattern`, `format` and `uniqueItems`. None of the schemas the route
 * tests check uses them; one that starts to needs modelling here first.
 *
 * A second, simpler subset validator lives in test_json_schema_subset.hpp (`schema_violation`,
 * used by the MCP output-schema tests). It is a different checker with different semantics: it
 * returns the first violation only, accepts a `type` array, and models neither `$ref`, `allOf`,
 * `oneOf` nor the bounds. Do not assume a schema that passes one passes the other.
 *
 * It returns the list of violations (empty = the body conforms) rather than asserting, so a
 * test can both require an empty list and prove, on a hand-made bad body, that each kind of
 * violation is caught.
 */

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace yuzu::test::openapi {

using json = nlohmann::json;

namespace detail {

inline const json* resolve_local_ref(const json& spec, const std::string& ref) {
    if (ref.rfind("#/", 0) != 0)
        return nullptr;
    const json* node = &spec;
    std::size_t pos = 2;
    while (pos <= ref.size()) {
        const auto slash = ref.find('/', pos);
        std::string seg = ref.substr(pos, slash == std::string::npos ? slash : slash - pos);
        for (std::size_t i = 0; (i = seg.find("~1", i)) != std::string::npos;)
            seg.replace(i, 2, "/");
        for (std::size_t i = 0; (i = seg.find("~0", i)) != std::string::npos;)
            seg.replace(i, 2, "~");
        if (!node->is_object() || !node->contains(seg))
            return nullptr;
        node = &(*node)[seg];
        if (slash == std::string::npos)
            break;
        pos = slash + 1;
    }
    return node;
}

/// Keywords accepted without being checked: pure annotations, plus `pattern`, `format` and
/// `uniqueItems`, which DO constrain a value but are not modelled (see the header).
inline bool is_annotation_keyword(const std::string& k) {
    static const std::set<std::string> kNames = {
        "description", "default",  "example",  "examples", "title",     "format",
        "pattern",     "readOnly", "writeOnly", "deprecated", "uniqueItems", "externalDocs"};
    return kNames.contains(k) || k.rfind("x-", 0) == 0;
}

inline bool is_modelled_keyword(const std::string& k) {
    static const std::set<std::string> kNames = {
        "$ref",     "allOf",    "oneOf",     "anyOf",     "type",      "nullable", "enum",
        "minimum",  "maximum",  "minLength", "maxLength", "minItems", "maxItems", "properties",
        "required", "items",    "additionalProperties"};
    return kNames.contains(k);
}

inline const char* json_type_name(const json& v) {
    if (v.is_null())
        return "null";
    if (v.is_boolean())
        return "boolean";
    if (v.is_number_integer())
        return "integer";
    if (v.is_number())
        return "number";
    if (v.is_string())
        return "string";
    if (v.is_array())
        return "array";
    return "object";
}

inline bool type_matches(const std::string& t, const json& v) {
    if (t == "string")
        return v.is_string();
    if (t == "integer")
        return v.is_number_integer();
    if (t == "number")
        return v.is_number();
    if (t == "boolean")
        return v.is_boolean();
    if (t == "object")
        return v.is_object();
    if (t == "array")
        return v.is_array();
    return false;
}

inline void check(const json& spec, const json& schema, const json& value, const std::string& at,
                  std::vector<std::string>& out, int depth) {
    if (depth > 32) {
        out.push_back(at + ": schema nesting deeper than 32");
        return;
    }
    if (!schema.is_object()) {
        out.push_back(at + ": the schema is not an object");
        return;
    }
    if (schema.contains("$ref")) {
        const json* target = resolve_local_ref(spec, schema["$ref"].get<std::string>());
        if (!target) {
            out.push_back(at + ": unresolvable $ref " + schema["$ref"].get<std::string>());
            return;
        }
        check(spec, *target, value, at, out, depth + 1);
        return;
    }
    for (const auto& [k, v] : schema.items()) {
        (void)v;
        if (!is_modelled_keyword(k) && !is_annotation_keyword(k))
            out.push_back(at + ": schema keyword '" + k + "' is not modelled by this checker");
    }

    if (value.is_null() && schema.value("nullable", false))
        return;

    if (schema.contains("allOf")) {
        for (const auto& part : schema["allOf"])
            check(spec, part, value, at, out, depth + 1);
    }
    for (const char* key : {"oneOf", "anyOf"}) {
        if (!schema.contains(key))
            continue;
        bool any = false;
        for (const auto& part : schema[key]) {
            std::vector<std::string> sub;
            check(spec, part, value, at, sub, depth + 1);
            if (sub.empty()) {
                any = true;
                break;
            }
        }
        if (!any)
            out.push_back(at + ": matches none of the " + key + " alternatives");
    }

    if (schema.contains("type")) {
        const std::string t = schema["type"].get<std::string>();
        if (!type_matches(t, value)) {
            out.push_back(at + ": declared " + t + " but the body has " + json_type_name(value));
            return; // the keywords below assume the declared type
        }
    }
    if (schema.contains("enum")) {
        bool found = false;
        for (const auto& e : schema["enum"])
            found = found || e == value;
        if (!found)
            out.push_back(at + ": value " + value.dump() + " is not in the declared enum " +
                          schema["enum"].dump());
    }
    if (value.is_number()) {
        if (schema.contains("minimum") && value.get<double>() < schema["minimum"].get<double>())
            out.push_back(at + ": " + value.dump() + " is below the declared minimum");
        if (schema.contains("maximum") && value.get<double>() > schema["maximum"].get<double>())
            out.push_back(at + ": " + value.dump() + " is above the declared maximum");
    }
    if (value.is_string()) {
        const auto len = value.get_ref<const std::string&>().size();
        if (schema.contains("minLength") && len < schema["minLength"].get<std::size_t>())
            out.push_back(at + ": string shorter than the declared minLength");
        if (schema.contains("maxLength") && len > schema["maxLength"].get<std::size_t>())
            out.push_back(at + ": string longer than the declared maxLength");
    }
    if (value.is_array()) {
        if (schema.contains("minItems") && value.size() < schema["minItems"].get<std::size_t>())
            out.push_back(at + ": fewer items than the declared minItems");
        if (schema.contains("maxItems") && value.size() > schema["maxItems"].get<std::size_t>())
            out.push_back(at + ": more items than the declared maxItems");
        if (schema.contains("items")) {
            for (std::size_t i = 0; i < value.size(); ++i)
                check(spec, schema["items"], value[i], at + "[" + std::to_string(i) + "]", out,
                      depth + 1);
        }
    }
    if (value.is_object()) {
        const bool has_props = schema.contains("properties");
        if (schema.contains("required")) {
            for (const auto& r : schema["required"]) {
                if (!value.contains(r.get<std::string>()))
                    out.push_back(at + ": required member '" + r.get<std::string>() +
                                  "' is missing");
            }
        }
        const bool free_form = !has_props && !schema.contains("additionalProperties");
        for (const auto& [name, member] : value.items()) {
            const std::string where = at + "." + name;
            if (has_props && schema["properties"].contains(name)) {
                check(spec, schema["properties"][name], member, where, out, depth + 1);
                continue;
            }
            if (free_form)
                continue;
            if (schema.contains("additionalProperties")) {
                const json& ap = schema["additionalProperties"];
                if (ap.is_boolean()) {
                    if (!ap.get<bool>())
                        out.push_back(where + ": undeclared member (additionalProperties false)");
                } else {
                    check(spec, ap, member, where, out, depth + 1);
                }
                continue;
            }
            out.push_back(where + ": undeclared member");
        }
    }
}

} // namespace detail

/// The violations of `body` against `schema` (an OpenAPI 3.0 schema object, usually
/// {"$ref": "#/components/schemas/X"}), resolved against `spec`. Empty: the body conforms.
[[nodiscard]] inline std::vector<std::string> body_violations(const json& spec, const json& schema,
                                                              const json& body,
                                                              const std::string& root = "$") {
    std::vector<std::string> out;
    detail::check(spec, schema, body, root, out, 0);
    return out;
}

/// The schema a path's operation declares for its 200 JSON answer, e.g. ("/config", "get").
/// `path` is the OpenAPI path (without /api/v1). Returns a null json when it is not declared.
[[nodiscard]] inline json ok_response_schema(const json& spec, const std::string& path,
                                             const std::string& method) {
    if (!spec.contains("paths") || !spec["paths"].contains(path) ||
        !spec["paths"][path].contains(method))
        return json();
    const json& op = spec["paths"][path][method];
    if (!op.contains("responses") || !op["responses"].contains("200"))
        return json();
    const json& r = op["responses"]["200"];
    if (!r.contains("content") || !r["content"].contains("application/json") ||
        !r["content"]["application/json"].contains("schema"))
        return json();
    return r["content"]["application/json"]["schema"];
}

namespace detail {

inline void collect_declared(const json& spec, const json& schema, const std::string& at,
                             std::set<std::string>& out, int depth) {
    if (depth > 32 || !schema.is_object())
        return;
    if (schema.contains("$ref")) {
        if (const json* t = resolve_local_ref(spec, schema["$ref"].get<std::string>()))
            collect_declared(spec, *t, at, out, depth + 1);
        return;
    }
    for (const char* key : {"allOf", "oneOf", "anyOf"}) {
        if (schema.contains(key))
            for (const auto& part : schema[key])
                collect_declared(spec, part, at, out, depth + 1);
    }
    if (schema.contains("properties")) {
        for (const auto& [name, sub] : schema["properties"].items()) {
            const std::string p = at + "." + name;
            out.insert(p);
            collect_declared(spec, sub, p, out, depth + 1);
        }
    }
    if (schema.contains("items")) {
        const std::string p = at + "[]";
        out.insert(p);
        collect_declared(spec, schema["items"], p, out, depth + 1);
    }
}

inline void collect_seen(const json& value, const std::string& at, std::set<std::string>& out) {
    if (value.is_object()) {
        for (const auto& [name, member] : value.items()) {
            const std::string p = at + "." + name;
            out.insert(p);
            collect_seen(member, p, out);
        }
    } else if (value.is_array()) {
        for (const auto& e : value) {
            const std::string p = at + "[]";
            out.insert(p);
            collect_seen(e, p, out);
        }
    }
}

} // namespace detail

/// Every member path a schema DECLARES ("$.data.revision", "$.data.document.overrides[]", ...),
/// following $ref / allOf / oneOf / anyOf and array items. A free-form object (no `properties`)
/// contributes no children.
[[nodiscard]] inline std::set<std::string> declared_member_paths(const json& spec,
                                                                 const json& schema) {
    std::set<std::string> out;
    detail::collect_declared(spec, schema, "$", out, 0);
    return out;
}

/// Every member path a real body CONTAINS, in the same spelling. A test unions these over the
/// bodies it fetched and requires the union to cover declared_member_paths(): a declared member
/// no real body ever carried is a member this test never checked the type of.
[[nodiscard]] inline std::set<std::string> seen_member_paths(const json& body) {
    std::set<std::string> out;
    detail::collect_seen(body, "$", out);
    return out;
}

namespace detail {

inline void collect_required(const json& spec, const json& schema, std::set<std::string>& req,
                             std::vector<const json*>& props, int depth) {
    if (depth > 32 || !schema.is_object())
        return;
    if (schema.contains("$ref")) {
        if (const json* t = resolve_local_ref(spec, schema["$ref"].get<std::string>()))
            collect_required(spec, *t, req, props, depth + 1);
        return;
    }
    if (schema.contains("allOf"))
        for (const auto& part : schema["allOf"])
            collect_required(spec, part, req, props, depth + 1);
    if (schema.contains("required"))
        for (const auto& r : schema["required"])
            req.insert(r.get<std::string>());
    if (schema.contains("properties"))
        props.push_back(&schema["properties"]);
}

} // namespace detail

/// The members every body in `bodies` carries at `path` ("$", "$.data", "$.data.document", names
/// joined by '.') that the schema does NOT list as required there. The other direction of the
/// check body_violations() makes: a schema that under-declares `required` passes every real body,
/// so only this catches a required member dropped from the schema text. The caller names the
/// object levels worth checking; a level whose members are all optional by design (a PUT input
/// document whose omitted keys take defaults) is simply not asked about.
[[nodiscard]] inline std::set<std::string>
always_present_not_required(const json& spec, const json& schema, const std::vector<json>& bodies,
                            const std::string& path) {
    std::vector<std::string> steps;
    for (std::size_t start = 0; start <= path.size();) {
        const auto dot = path.find('.', start);
        const std::string tok = path.substr(start, dot == std::string::npos ? dot : dot - start);
        if (!tok.empty() && tok != "$")
            steps.push_back(tok);
        if (dot == std::string::npos)
            break;
        start = dot + 1;
    }
    // Schema side: follow the steps through properties (and $ref / allOf).
    json cur = schema;
    for (const auto& step : steps) {
        std::set<std::string> req;
        std::vector<const json*> props;
        detail::collect_required(spec, cur, req, props, 0);
        json next;
        for (const json* p : props)
            if (p->contains(step))
                next = (*p)[step];
        if (next.is_null())
            return {"<path not declared: " + path + ">"};
        cur = next;
    }
    std::set<std::string> required;
    std::vector<const json*> unused;
    detail::collect_required(spec, cur, required, unused, 0);

    // Body side: the intersection of member names across the bodies that have the object.
    std::optional<std::set<std::string>> common;
    for (const auto& b : bodies) {
        const json* node = &b;
        for (const auto& step : steps) {
            if (!node->is_object() || !node->contains(step)) {
                node = nullptr;
                break;
            }
            node = &(*node)[step];
        }
        if (!node || !node->is_object())
            return {"<path absent from a body: " + path + ">"};
        std::set<std::string> names;
        for (const auto& [k, v] : node->items()) {
            (void)v;
            names.insert(k);
        }
        if (!common) {
            common = names;
        } else {
            std::set<std::string> kept;
            for (const auto& n : *common)
                if (names.contains(n))
                    kept.insert(n);
            common = kept;
        }
    }
    std::set<std::string> gaps;
    for (const auto& n : common.value_or(std::set<std::string>{}))
        if (!required.contains(n))
            gaps.insert(n);
    return gaps;
}

} // namespace yuzu::test::openapi
