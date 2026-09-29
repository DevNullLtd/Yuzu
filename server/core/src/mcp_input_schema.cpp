#include "mcp_input_schema.hpp"

#include <re2/re2.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <utility>

namespace yuzu::server::mcp {

namespace detail {

enum class SchemaType { kString, kInteger, kNumber, kBoolean, kObject, kArray };

// One compiled subschema. Immutable after compile; validate() only reads.
struct SchemaNode {
    SchemaType type = SchemaType::kObject;
    // Declared order preserved so first-error selection is deterministic.
    std::vector<std::pair<std::string, std::unique_ptr<const SchemaNode>>> properties;
    std::vector<std::string> required;
    std::unique_ptr<const SchemaNode> items;
    std::optional<std::size_t> min_items;          // arrays
    std::optional<std::size_t> max_items;          // arrays
    std::unique_ptr<const SchemaNode> additional;  // additionalProperties value-schema
    bool additional_forbidden = false;             // additionalProperties:false
    std::vector<std::vector<std::string>> any_of;  // required-only alternatives
    std::optional<double> minimum;
    std::optional<double> maximum;
    std::optional<std::size_t> min_length;  // bytes
    std::optional<std::size_t> max_length;  // bytes
    std::vector<nlohmann::json> enum_values;
    std::unique_ptr<RE2> pattern;  // precompiled; RE2 matching is const-thread-safe
};

}  // namespace detail

namespace {

using detail::SchemaNode;
using detail::SchemaType;

// Schema-nesting cap (edges from the root). Bounds compile recursion on a
// hostile/buggy schema string; the deepest served schema today is 4 edges
// (execute_bundle: root → steps items → params → additionalProperties leaf).
constexpr int kMaxSchemaDepth = 8;

// The CLOSED keyword catalogue (see header). Anything else is a compile error.
constexpr std::string_view kSupportedKeywords[] = {
    "type",     "properties", "required",  "description",          "default",
    "enum",     "minimum",    "maximum",   "minLength",            "maxLength",
    "pattern",  "items",      "minItems",  "maxItems",             "anyOf",
    "additionalProperties"};

std::optional<SchemaType> parse_type(std::string_view t) {
    if (t == "string")
        return SchemaType::kString;
    if (t == "integer")
        return SchemaType::kInteger;
    if (t == "number")
        return SchemaType::kNumber;
    if (t == "boolean")
        return SchemaType::kBoolean;
    if (t == "object")
        return SchemaType::kObject;
    if (t == "array")
        return SchemaType::kArray;
    return std::nullopt;
}

std::string fmt_bound(double d) {
    if (d == std::floor(d) && std::abs(d) < 9.0e18)
        return std::to_string(static_cast<long long>(d));
    return std::to_string(d);
}

// Recursive compiler. Accumulates every problem into `errors` (never throws,
// never stops at the first offence) so the boot validator can report all
// schema offences in one deterministic message. Returns a best-effort node;
// the caller discards it unless `errors` stayed empty.
std::unique_ptr<const SchemaNode> compile_node(const nlohmann::json& s, const std::string& path,
                                               int depth, std::vector<std::string>& errors) {
    auto err = [&](std::string msg) { errors.push_back(std::move(msg)); };

    if (depth > kMaxSchemaDepth) {
        err("schema nesting at '" + path + "' exceeds the supported depth of " +
            std::to_string(kMaxSchemaDepth));
        return nullptr;
    }
    if (!s.is_object()) {
        err("schema at '" + path + "' is not an object");
        return nullptr;
    }

    auto node = std::make_unique<SchemaNode>();

    for (const auto& [key, value] : s.items()) {
        (void)value;
        if (std::find(std::begin(kSupportedKeywords), std::end(kSupportedKeywords), key) ==
            std::end(kSupportedKeywords))
            err("unsupported keyword '" + key + "' at '" + path + "'");
    }

    // ── type (mandatory on every compiled node) ─────────────────────────
    bool type_known = false;
    if (!s.contains("type")) {
        err("schema at '" + path + "' has no 'type'");
    } else if (!s["type"].is_string()) {
        err("'type' at '" + path + "' must be a single string (unions are unsupported)");
    } else if (auto ty = parse_type(s["type"].get_ref<const std::string&>())) {
        node->type = *ty;
        type_known = true;
    } else {
        err("unsupported type '" + s["type"].get_ref<const std::string&>() + "' at '" + path +
            "'");
    }
    auto type_is = [&](SchemaType t) { return type_known && node->type == t; };
    auto require_type = [&](const char* keyword, SchemaType t, const char* type_name) {
        if (type_known && node->type != t)
            err(std::string("keyword '") + keyword + "' at '" + path + "' requires type '" +
                type_name + "'");
    };

    // ── properties ──────────────────────────────────────────────────────
    if (s.contains("properties")) {
        require_type("properties", SchemaType::kObject, "object");
        if (!s["properties"].is_object()) {
            err("'properties' at '" + path + "' must be an object");
        } else {
            for (const auto& [name, sub] : s["properties"].items())
                node->properties.emplace_back(
                    name, compile_node(sub, path + "/properties/" + name, depth + 1, errors));
        }
    }
    auto declares_property = [&](std::string_view name) {
        return std::any_of(node->properties.begin(), node->properties.end(),
                           [&](const auto& p) { return p.first == name; });
    };

    // ── required (names must be declared — Yuzu authoring lint) ─────────
    if (s.contains("required")) {
        require_type("required", SchemaType::kObject, "object");
        if (!s["required"].is_array()) {
            err("'required' at '" + path + "' must be an array");
        } else {
            for (const auto& entry : s["required"]) {
                if (!entry.is_string()) {
                    err("'required' entries at '" + path + "' must be strings");
                    continue;
                }
                const auto& name = entry.get_ref<const std::string&>();
                if (std::find(node->required.begin(), node->required.end(), name) !=
                    node->required.end()) {
                    err("duplicate 'required' entry '" + name + "' at '" + path + "'");
                    continue;
                }
                if (!declares_property(name))
                    err("schema at '" + path + "' requires '" + name +
                        "' which is not declared in 'properties'");
                node->required.push_back(name);
            }
        }
    }

    // ── enum (scalar types only) ────────────────────────────────────────
    if (s.contains("enum")) {
        if (type_is(SchemaType::kObject) || type_is(SchemaType::kArray))
            err("keyword 'enum' at '" + path + "' is not supported on object/array schemas");
        if (!s["enum"].is_array() || s["enum"].empty())
            err("'enum' at '" + path + "' must be a non-empty array");
        else
            for (const auto& v : s["enum"])
                node->enum_values.push_back(v);
    }

    // ── minimum / maximum (numeric types only) ──────────────────────────
    for (const char* kw : {"minimum", "maximum"}) {
        if (!s.contains(kw))
            continue;
        if (type_known && node->type != SchemaType::kInteger &&
            node->type != SchemaType::kNumber)
            err(std::string("keyword '") + kw + "' at '" + path +
                "' requires type 'integer' or 'number'");
        if (!s[kw].is_number()) {
            err(std::string("'") + kw + "' at '" + path + "' must be a number");
            continue;
        }
        (kw == std::string_view{"minimum"} ? node->minimum : node->maximum) =
            s[kw].get<double>();
    }
    if (node->minimum && node->maximum && *node->minimum > *node->maximum)
        err("'minimum' exceeds 'maximum' at '" + path + "'");

    // ── minLength / maxLength (string only; bytes) ──────────────────────
    for (const char* kw : {"minLength", "maxLength"}) {
        if (!s.contains(kw))
            continue;
        require_type(kw, SchemaType::kString, "string");
        if (!s[kw].is_number_integer() || s[kw].get<std::int64_t>() < 0) {
            err(std::string("'") + kw + "' at '" + path + "' must be a non-negative integer");
            continue;
        }
        (kw == std::string_view{"minLength"} ? node->min_length : node->max_length) =
            static_cast<std::size_t>(s[kw].get<std::int64_t>());
    }
    if (node->min_length && node->max_length && *node->min_length > *node->max_length)
        err("'minLength' exceeds 'maxLength' at '" + path + "'");

    // ── pattern (string only; RE2, precompiled) ─────────────────────────
    if (s.contains("pattern")) {
        require_type("pattern", SchemaType::kString, "string");
        if (!s["pattern"].is_string()) {
            err("'pattern' at '" + path + "' must be a string");
        } else {
            RE2::Options opts;
            opts.set_log_errors(false);
            auto re = std::make_unique<RE2>(s["pattern"].get_ref<const std::string&>(), opts);
            if (!re->ok())
                err("'pattern' at '" + path + "' does not compile as RE2");
            else
                node->pattern = std::move(re);
        }
    }

    // ── items / minItems / maxItems (array only) ────────────────────────
    if (s.contains("items")) {
        require_type("items", SchemaType::kArray, "array");
        if (!s["items"].is_object())
            err("'items' at '" + path + "' must be an object schema");
        else
            node->items = compile_node(s["items"], path + "/items", depth + 1, errors);
    }
    for (const char* kw : {"minItems", "maxItems"}) {
        if (!s.contains(kw))
            continue;
        require_type(kw, SchemaType::kArray, "array");
        if (!s[kw].is_number_integer() || s[kw].get<std::int64_t>() < 0) {
            err(std::string("'") + kw + "' at '" + path + "' must be a non-negative integer");
            continue;
        }
        (kw == std::string_view{"minItems"} ? node->min_items : node->max_items) =
            static_cast<std::size_t>(s[kw].get<std::int64_t>());
    }
    if (node->min_items && node->max_items && *node->min_items > *node->max_items)
        err("'minItems' exceeds 'maxItems' at '" + path + "'");

    // ── additionalProperties (object only; schema-form or false) ────────
    if (s.contains("additionalProperties")) {
        require_type("additionalProperties", SchemaType::kObject, "object");
        const auto& ap = s["additionalProperties"];
        if (ap.is_object()) {
            node->additional =
                compile_node(ap, path + "/additionalProperties", depth + 1, errors);
        } else if (ap.is_boolean() && !ap.get<bool>()) {
            node->additional_forbidden = true;
        } else {
            err("'additionalProperties' at '" + path +
                "' must be an object schema or false ('true' is unsupported — omit it)");
        }
    }

    // ── anyOf (object only; required-only alternatives) ─────────────────
    if (s.contains("anyOf")) {
        require_type("anyOf", SchemaType::kObject, "object");
        if (!s["anyOf"].is_array() || s["anyOf"].empty()) {
            err("'anyOf' at '" + path + "' must be a non-empty array");
        } else {
            for (const auto& alt : s["anyOf"]) {
                if (!alt.is_object() || alt.size() != 1 || !alt.contains("required") ||
                    !alt["required"].is_array() || alt["required"].empty()) {
                    err("each 'anyOf' alternative at '" + path +
                        "' must be an object containing only a non-empty 'required' array");
                    continue;
                }
                std::vector<std::string> names;
                bool ok = true;
                for (const auto& entry : alt["required"]) {
                    if (!entry.is_string()) {
                        err("'anyOf' alternative 'required' entries at '" + path +
                            "' must be strings");
                        ok = false;
                        break;
                    }
                    const auto& name = entry.get_ref<const std::string&>();
                    if (!declares_property(name))
                        err("'anyOf' alternative at '" + path + "' requires '" + name +
                            "' which is not declared in 'properties'");
                    names.push_back(name);
                }
                if (ok)
                    node->any_of.push_back(std::move(names));
            }
        }
    }

    return node;
}

// Recursive first-error validation of an instance value against a compiled
// node. `path` is INSTANCE-space (see SchemaViolation contract): declared
// property names and numeric array indices verbatim; caller-derived map keys
// always as '*'.
std::optional<SchemaViolation> validate_node(const SchemaNode& n, const nlohmann::json& v,
                                             const std::string& path) {
    switch (n.type) {
    case SchemaType::kObject:
        if (!v.is_object())
            return SchemaViolation{path, "expected an object"};
        break;
    case SchemaType::kArray:
        if (!v.is_array())
            return SchemaViolation{path, "expected an array"};
        break;
    case SchemaType::kString:
        if (!v.is_string())
            return SchemaViolation{path, "expected a string"};
        break;
    case SchemaType::kBoolean:
        if (!v.is_boolean())
            return SchemaViolation{path, "expected a boolean"};
        break;
    case SchemaType::kInteger:
        if (!v.is_number_integer())
            return SchemaViolation{
                path, v.is_number()
                          ? "expected an integer (integral floats such as 1.0 are not accepted)"
                          : "expected an integer"};
        if (v.is_number_unsigned() &&
            v.get<std::uint64_t>() >
                static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
            return SchemaViolation{path, "integer is outside the signed 64-bit range"};
        break;
    case SchemaType::kNumber:
        if (!v.is_number())
            return SchemaViolation{path, "expected a number"};
        break;
    }

    if (!n.enum_values.empty()) {
        const bool hit = std::any_of(n.enum_values.begin(), n.enum_values.end(),
                                     [&](const nlohmann::json& e) { return e == v; });
        if (!hit) {
            std::string allowed;
            for (const auto& e : n.enum_values) {
                if (!allowed.empty())
                    allowed += ", ";
                allowed += e.dump();
            }
            return SchemaViolation{path, "value must be one of: " + allowed};
        }
    }

    if (v.is_string()) {
        const auto& str = v.get_ref<const std::string&>();
        if (n.min_length && str.size() < *n.min_length)
            return SchemaViolation{path, "string is shorter than minLength " +
                                             std::to_string(*n.min_length) + " (bytes)"};
        if (n.max_length && str.size() > *n.max_length)
            return SchemaViolation{path, "string exceeds maxLength " +
                                             std::to_string(*n.max_length) + " (bytes)"};
        // JSON Schema 'pattern' is a SEARCH (unanchored), so PartialMatch —
        // the served patterns anchor themselves with ^...$ where they mean to.
        if (n.pattern && !RE2::PartialMatch(str, *n.pattern))
            return SchemaViolation{path, "string does not match the required pattern"};
    }

    if (v.is_number() && (n.minimum || n.maximum)) {
        const double d = v.get<double>();
        if (n.minimum && d < *n.minimum)
            return SchemaViolation{path, "value is below the minimum " + fmt_bound(*n.minimum)};
        if (n.maximum && d > *n.maximum)
            return SchemaViolation{path, "value is above the maximum " + fmt_bound(*n.maximum)};
    }

    if (v.is_object()) {
        for (const auto& name : n.required)
            if (!v.contains(name))
                return SchemaViolation{path, "missing required property '" + name + "'"};
        for (const auto& [name, sub] : n.properties) {
            if (!sub)
                continue;  // compile error already reported; unreachable in production
            if (auto it = v.find(name); it != v.end())
                if (auto violation = validate_node(*sub, *it, path + "/" + name))
                    return violation;
        }
        if (n.additional_forbidden || n.additional) {
            for (const auto& [key, value] : v.items()) {
                if (std::any_of(n.properties.begin(), n.properties.end(),
                                [&](const auto& p) { return p.first == key; }))
                    continue;
                // Caller-derived key: report as '*', never the key itself.
                if (n.additional_forbidden)
                    return SchemaViolation{path + "/*",
                                           "unexpected property (additional properties are "
                                           "not allowed here)"};
                if (auto violation = validate_node(*n.additional, value, path + "/*"))
                    return violation;
            }
        }
        if (!n.any_of.empty()) {
            const bool satisfied =
                std::any_of(n.any_of.begin(), n.any_of.end(), [&](const auto& alt) {
                    return std::all_of(alt.begin(), alt.end(),
                                       [&](const std::string& name) { return v.contains(name); });
                });
            if (!satisfied) {
                std::string alts;
                for (const auto& alt : n.any_of) {
                    if (!alts.empty())
                        alts += "; ";
                    alts += "required [";
                    for (size_t i = 0; i < alt.size(); ++i) {
                        if (i)
                            alts += ", ";
                        alts += alt[i];
                    }
                    alts += "]";
                }
                return SchemaViolation{path,
                                       "value satisfies none of the anyOf alternatives: " + alts};
            }
        }
    }

    if (v.is_array()) {
        if (n.min_items && v.size() < *n.min_items)
            return SchemaViolation{path, "array is below the minItems " +
                                             std::to_string(*n.min_items) + " (items)"};
        if (n.max_items && v.size() > *n.max_items)
            return SchemaViolation{path, "array exceeds maxItems " +
                                             std::to_string(*n.max_items) + " (items)"};
        if (n.items)
            for (std::size_t i = 0; i < v.size(); ++i)
                if (auto violation =
                        validate_node(*n.items, v[i], path + "/" + std::to_string(i)))
                    return violation;
    }

    return std::nullopt;
}

}  // namespace

CompiledInputSchema::CompiledInputSchema(std::unique_ptr<const detail::SchemaNode> root)
    : root_(std::move(root)) {}
CompiledInputSchema::CompiledInputSchema(CompiledInputSchema&&) noexcept = default;
CompiledInputSchema& CompiledInputSchema::operator=(CompiledInputSchema&&) noexcept = default;
CompiledInputSchema::~CompiledInputSchema() = default;

std::optional<SchemaViolation> CompiledInputSchema::validate(const nlohmann::json& args) const {
    if (!root_)  // defensive: compile_input_schema never hands out a null root
        return SchemaViolation{"", "schema unavailable"};
    return validate_node(*root_, args, "");
}

std::size_t supported_keyword_count() {
    return std::size(kSupportedKeywords);
}

std::expected<CompiledInputSchema, std::vector<std::string>>
compile_input_schema(std::string_view schema_json) {
    std::vector<std::string> errors;
    const auto parsed = nlohmann::json::parse(schema_json, nullptr, /*allow_exceptions=*/false);
    if (parsed.is_discarded()) {
        errors.emplace_back("input schema is not valid JSON");
        return std::unexpected(std::move(errors));
    }
    if (parsed.is_object() && parsed.contains("type") && parsed["type"].is_string() &&
        parsed["type"].get_ref<const std::string&>() != "object")
        errors.emplace_back("input schema root is not an object schema");
    auto root = compile_node(parsed, "", 0, errors);
    if (!errors.empty())
        return std::unexpected(std::move(errors));
    return CompiledInputSchema(std::move(root));
}

}  // namespace yuzu::server::mcp
