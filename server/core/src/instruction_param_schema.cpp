#include "instruction_param_schema.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <exception>
#include <limits>
#include <utility>

#include <re2/re2.h>

#include <yuzu/server/auth.hpp>  // AuthManager::sha256_hex: the repo's shared SHA-256 helper

#include "mcp_jsonrpc.hpp"

namespace yuzu::server::instr {

namespace {

using nlohmann::json;

// How a declared parameter's JSON value is coerced before the shared validator sees it.
enum class Kind { kString, kInteger, kBoolean, kArray };
enum class Subtype { kPlain, kInt32, kDatetime, kGuid };

struct PropInfo {
    std::string name;
    Kind kind = Kind::kString;
    bool has_default = false;
    // The property's pattern (user-authored, or the fixed datetime/guid one) and its RE2
    // program size, and the same for an array property's `items`; check() weighs a string
    // matched against them. Enum member counts are charged per string too (guard_string).
    bool has_pattern = false;
    std::size_t pattern_prog = 0;
    bool items_has_pattern = false;
    std::size_t items_pattern_prog = 0;
    std::size_t enum_members = 0;
    std::size_t items_enum_members = 0;
};

// Same nesting limit instruction_store.cpp applies to a parameter_schema at import.
constexpr int kMaxStoredSchemaDepth = mcp::kMcpMaxJsonDepth;
// "-9223372036854775808" is 20 characters.
constexpr std::size_t kMaxIntegerStringLen = 20;
constexpr std::int64_t kInt32Min = std::numeric_limits<std::int32_t>::min();
constexpr std::int64_t kInt32Max = std::numeric_limits<std::int32_t>::max();

// RE2 `$` is end-of-text, so a trailing newline does not match.
constexpr std::string_view kDatetimePattern =
    "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
    "T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)(\\.[0-9]+)?"
    "(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$";
constexpr std::string_view kGuidPattern =
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";

// Closed keyword sets. Anything outside them is an error (fail closed).
constexpr std::string_view kRootKeys[] = {"type", "properties", "required", "description"};
constexpr std::string_view kPropKeys[] = {
    "type",    "description", "displayName", "hidden",  "validation", "default", "enum",
    "minimum", "maximum",     "minLength",   "maxLength", "pattern",   "items",   "required"};
constexpr std::string_view kValidationKeys[] = {"maxLength", "minLength", "pattern",
                                                "enum",      "minimum",   "maximum"};
constexpr std::string_view kItemKeys[] = {"type",    "description", "enum",
                                          "pattern", "minLength",   "maxLength"};

template <std::size_t N>
bool in_set(const std::string_view (&set)[N], std::string_view key) {
    return std::find(std::begin(set), std::end(set), key) != std::end(set);
}

struct TypeInfo {
    Kind kind;
    const char* canonical;  // JSON-Schema type name
    Subtype subtype;
};

std::optional<TypeInfo> parse_param_type(std::string_view t) {
    if (t == "string")
        return TypeInfo{Kind::kString, "string", Subtype::kPlain};
    if (t == "integer" || t == "int64")
        return TypeInfo{Kind::kInteger, "integer", Subtype::kPlain};
    if (t == "int32")
        return TypeInfo{Kind::kInteger, "integer", Subtype::kInt32};
    if (t == "boolean")
        return TypeInfo{Kind::kBoolean, "boolean", Subtype::kPlain};
    if (t == "array")
        return TypeInfo{Kind::kArray, "array", Subtype::kPlain};
    if (t == "datetime")
        return TypeInfo{Kind::kString, "string", Subtype::kDatetime};
    if (t == "guid")
        return TypeInfo{Kind::kString, "string", Subtype::kGuid};
    return std::nullopt;
}

std::string_view trim(std::string_view s) {
    constexpr std::string_view kWs = " \t\r\n";
    const auto b = s.find_first_not_of(kWs);
    if (b == std::string_view::npos)
        return {};
    return s.substr(b, s.find_last_not_of(kWs) - b + 1);
}

// `-?[0-9]+`, ASCII digits only, bounded length, parsed without overflow.
std::optional<std::int64_t> parse_decimal_int(const std::string& s) {
    if (s.empty() || s.size() > kMaxIntegerStringLen)
        return std::nullopt;
    const std::size_t first_digit = (s[0] == '-') ? 1 : 0;
    if (first_digit == s.size())
        return std::nullopt;
    for (std::size_t i = first_digit; i < s.size(); ++i)
        if (s[i] < '0' || s[i] > '9')
            return std::nullopt;
    std::int64_t v = 0;
    const char* const end = s.data() + s.size();
    const auto [ptr, ec] = std::from_chars(s.data(), end, v);
    if (ec != std::errc{} || ptr != end)
        return std::nullopt;
    return v;
}

// ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$. The bound keeps a name safe to put in error text and
// audit detail (no whitespace, control, quote or '=' bytes).
bool valid_param_name(std::string_view n) {
    if (n.empty() || n.size() > 64)
        return false;
    auto alnum_us = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '_';
    };
    return alnum_us(n[0]) && std::all_of(n.begin() + 1, n.end(), [&](char c) {
               return alnum_us(c) || c == '.' || c == '-';
           });
}

// enum on a string-typed node: a non-empty array whose members are all strings.
bool valid_string_enum(const json& e) {
    return e.is_array() && !e.empty() &&
           std::all_of(e.begin(), e.end(), [](const json& m) { return m.is_string(); });
}

// A bound of magnitude 2^53 or more cannot be enforced exactly (the shared validator
// compares as doubles). Integers are compared exactly; a NaN float counts as exceeding.
bool bound_exceeds_exact_range(const json& b) {
    constexpr std::int64_t kLim = kIntegerBoundLimit;
    if (b.is_number_unsigned())
        return b.get<std::uint64_t>() >= static_cast<std::uint64_t>(kLim);
    if (b.is_number_integer()) {
        const auto v = b.get<std::int64_t>();
        return v >= kLim || v <= -kLim;
    }
    if (b.is_number_float())
        return !(std::fabs(b.get<double>()) < static_cast<double>(kLim));
    return false;
}

RE2::Options pattern_options() {
    RE2::Options o;
    o.set_log_errors(false);
    o.set_max_mem(mcp::kPatternMaxMem);
    return o;
}

// RE2 program size of a fixed datetime/guid pattern, compiled once. On the (impossible)
// failure to compile, the per-pattern ceiling is used so the work estimate stays conservative.
std::size_t fixed_pattern_program(Subtype t) {
    const auto size_of = [](std::string_view p) {
        const RE2 re{std::string(p), pattern_options()};
        return re.ok() ? static_cast<std::size_t>(re.ProgramSize()) : kMaxPatternProgramSize;
    };
    static const std::size_t dt = size_of(kDatetimePattern);
    static const std::size_t guid = size_of(kGuidPattern);
    return t == Subtype::kDatetime ? dt : guid;
}

// Running state of the pattern pre-compile of ONE schema.
struct PatternBudget {
    std::size_t user_program = 0;  // sum of user pattern program sizes
    bool exhausted = false;        // a budget failure was reported: stop compiling
    // false: canonicalise only (canonicalise_param_schema). No pattern is compiled or sized;
    // the shape, size and depth limits still apply.
    bool compile = true;
};

// Pre-compile one USER pattern under the shared RE2 budget. Returns its program size, or
// nullopt after appending an error that names the limit and never the pattern (RE2's own
// error text embeds it). Once any budget failure is reported nothing further is compiled.
std::optional<std::size_t> vet_pattern(const std::string& pattern, const std::string& at,
                                       const char* label, PatternBudget& budget,
                                       std::vector<std::string>& errors) {
    if (budget.exhausted)
        return std::nullopt;
    if (!budget.compile)
        return std::size_t{0};
    const RE2 re(pattern, pattern_options());
    if (!re.ok()) {
        if (re.error_code() == RE2::ErrorPatternTooLarge) {
            budget.exhausted = true;
            errors.push_back(at + label + " needs more than " +
                             std::to_string(mcp::kPatternMaxMem) +
                             " bytes of RE2 memory to compile");
        } else {
            errors.push_back(at + label + " does not compile as RE2");
        }
        return std::nullopt;
    }
    const auto size = static_cast<std::size_t>(re.ProgramSize());
    if (size > kMaxPatternProgramSize) {
        budget.exhausted = true;
        errors.push_back(at + label + " compiles to a program larger than " +
                         std::to_string(kMaxPatternProgramSize) + " instructions");
        return std::nullopt;
    }
    if (size > kMaxSchemaPatternProgramSize - budget.user_program) {
        budget.exhausted = true;
        errors.push_back(at + label + " takes the schema's patterns past " +
                         std::to_string(kMaxSchemaPatternProgramSize) +
                         " compiled instructions in total");
        return std::nullopt;
    }
    budget.user_program += size;
    return size;
}

// Tighten a numeric bound toward the int32 range. A declared bound that is not a number is
// left for the shared compiler to reject.
void tighten_bound(json& node, const char* key, std::int64_t limit, bool is_min) {
    auto it = node.find(key);
    if (it == node.end()) {
        node[key] = limit;
    } else if (it->is_number()) {
        const double declared = it->get<double>();
        const double lim = static_cast<double>(limit);
        if (is_min ? declared < lim : declared > lim)
            *it = limit;
    }
}

// The enum/pattern checks shared by a property and its `items`. Returns true when the key
// was fully handled here (accepted into `out`, or an error appended).
bool take_enum_or_pattern(const std::string& key, const json& value, const std::string& at,
                          bool items, std::size_t& enum_members, bool& has_pattern,
                          std::size_t& pattern_prog, json& out, PatternBudget& budget,
                          std::vector<std::string>& errors) {
    if (key == "enum") {
        const std::string label = items ? "'items' enum " : "'enum' ";
        if (!valid_string_enum(value))
            errors.push_back(at + label + "must be a non-empty array of strings");
        else if (value.size() > kMaxEnumMembers)
            errors.push_back(at + label + "has more than " + std::to_string(kMaxEnumMembers) +
                             " members");
        else {
            out["enum"] = value;
            enum_members = value.size();
        }
        return true;
    }
    if (key == "pattern" && value.is_string()) {
        const char* label = items ? "'items' pattern" : "'pattern'";
        const auto& p = value.get_ref<const std::string&>();
        if (p.size() > kMaxPatternBytes) {
            errors.push_back(at + label + " is longer than " + std::to_string(kMaxPatternBytes) +
                             " bytes");
        } else if (const auto size = vet_pattern(p, at, label, budget, errors)) {
            has_pattern = true;
            pattern_prog = *size;
            out["pattern"] = value;
        }
        return true;
    }
    return false;
}

json canonicalise_items(const std::string& name, const json& items, PropInfo& info,
                        PatternBudget& budget, std::vector<std::string>& errors) {
    const std::string at = "parameter '" + name + "': ";
    json out = json::object();
    if (!items.is_object()) {
        errors.push_back(at + "'items' must be an object");
        return out;
    }
    for (const auto& [key, value] : items.items()) {
        if (!in_set(kItemKeys, key))
            errors.push_back(at + "'items' has an unsupported keyword");
        else if (key == "type")
            continue;  // validated below
        else if (!take_enum_or_pattern(key, value, at, true, info.items_enum_members,
                                       info.items_has_pattern, info.items_pattern_prog, out,
                                       budget, errors))
            out[key] = value;
    }
    if (!items.contains("type") || !items["type"].is_string() ||
        items["type"].get_ref<const std::string&>() != "string")
        errors.push_back(at + "'items' must declare type 'string' (the only supported item type)");
    out["type"] = "string";
    return out;
}

struct PropResult {
    json canonical = json::object();
    PropInfo info;
    bool inline_required = false;
};

PropResult canonicalise_property(const std::string& name, const json& spec, PatternBudget& budget,
                                 std::vector<std::string>& errors) {
    PropResult r;
    r.info.name = name;
    if (!valid_param_name(name)) {
        // Deliberately does not echo the name: it is schema-author text.
        errors.push_back("a parameter name is not 1-64 characters of [A-Za-z0-9_.-] "
                         "starting with [A-Za-z0-9_]");
        return r;
    }
    const std::string at = "parameter '" + name + "': ";
    if (!spec.is_object()) {
        errors.push_back(at + "descriptor is not an object");
        return r;
    }
    for (const auto& [key, value] : spec.items()) {
        (void)value;
        if (!in_set(kPropKeys, key))
            errors.push_back(at + "has an unsupported keyword");
    }

    std::optional<TypeInfo> ti;
    if (!spec.contains("type") || !spec["type"].is_string())
        errors.push_back(at + "'type' is missing or not a string");
    else if (!(ti = parse_param_type(spec["type"].get_ref<const std::string&>())))
        errors.push_back(at + "has an unsupported type");
    if (!ti)
        return r;
    r.info.kind = ti->kind;
    r.canonical["type"] = ti->canonical;
    const bool string_kind = ti->kind == Kind::kString;

    if (spec.contains("description")) {
        if (!spec["description"].is_string())
            errors.push_back(at + "'description' must be a string");
        else
            r.canonical["description"] = spec["description"];
    }
    if (spec.contains("default")) {
        r.info.has_default = true;
        r.canonical["default"] = spec["default"];
    }
    if (spec.contains("required")) {
        if (!spec["required"].is_boolean())
            errors.push_back(at + "inline 'required' must be a boolean");
        else
            r.inline_required = spec["required"].get<bool>();
    }

    // Constraints: validation{} overlaid by the FLAT keys (flat wins).
    json merged = json::object();
    if (spec.contains("validation")) {
        if (!spec["validation"].is_object()) {
            errors.push_back(at + "'validation' must be an object");
        } else {
            for (const auto& [key, value] : spec["validation"].items()) {
                if (!in_set(kValidationKeys, key))
                    errors.push_back(at + "'validation' has an unsupported keyword");
                else
                    merged[key] = value;
            }
        }
    }
    for (const auto key : kValidationKeys)
        if (spec.contains(std::string(key)))
            merged[std::string(key)] = spec[std::string(key)];

    const bool fixed_pattern = ti->subtype == Subtype::kDatetime || ti->subtype == Subtype::kGuid;
    for (const auto& [key, value] : merged.items()) {
        if (key == "enum" && !string_kind) {
            errors.push_back(at + "'enum' is only supported on string-typed parameters");
        } else if (key == "pattern" && fixed_pattern) {
            errors.push_back(at + "'pattern' is not allowed on a datetime or guid parameter");
        } else if ((key == "minimum" || key == "maximum") && ti->kind == Kind::kInteger &&
                   bound_exceeds_exact_range(value)) {
            errors.push_back(at + "'" + key + "' must be strictly inside the exactly " +
                             "representable integer range (|bound| < 2^53)");
        } else if (!take_enum_or_pattern(key, value, at, false, r.info.enum_members,
                                         r.info.has_pattern, r.info.pattern_prog, r.canonical,
                                         budget, errors)) {
            // The shared compiler enforces keyword/type compatibility and operand shape.
            r.canonical[key] = value;
        }
    }

    if (fixed_pattern) {
        r.canonical["pattern"] = std::string(ti->subtype == Subtype::kDatetime ? kDatetimePattern
                                                                               : kGuidPattern);
        r.info.has_pattern = true;
        r.info.pattern_prog = budget.compile ? fixed_pattern_program(ti->subtype) : 0;
    } else if (ti->subtype == Subtype::kInt32) {
        tighten_bound(r.canonical, "minimum", kInt32Min, /*is_min=*/true);
        tighten_bound(r.canonical, "maximum", kInt32Max, /*is_min=*/false);
    }

    if (spec.contains("items")) {
        if (ti->kind != Kind::kArray)
            errors.push_back(at + "'items' is only supported on array parameters");
        else
            r.canonical["items"] = canonicalise_items(name, spec["items"], r.info, budget, errors);
    }
    return r;
}

// Canonicalise the whole stored root into `out`; fills `props`. The caller discards `out`
// when `errors` is non-empty.
void canonicalise_root(const json& root, json& out, std::vector<PropInfo>& props,
                       PatternBudget& budget, std::vector<std::string>& errors) {
    for (const auto& [key, value] : root.items()) {
        (void)value;
        if (!in_set(kRootKeys, key))
            errors.push_back("parameters root has an unsupported keyword");
    }
    if (!root.contains("type") || !root["type"].is_string() ||
        root["type"].get_ref<const std::string&>() != "object")
        errors.push_back("parameters root 'type' must be \"object\"");
    if (root.contains("description") && !root["description"].is_string())
        errors.push_back("parameters root 'description' must be a string");

    json properties = json::object();
    std::vector<std::string> required;
    std::vector<std::string> defaulted;
    std::vector<std::string> inline_required;

    if (root.contains("properties")) {
        if (!root["properties"].is_object()) {
            errors.push_back("parameters root 'properties' must be an object");
        } else if (root["properties"].size() > kMaxSchemaProperties) {
            // Return now: with the properties skipped every `required` name would be
            // reported as undeclared, which would mislead.
            errors.push_back("parameters root declares more than " +
                             std::to_string(kMaxSchemaProperties) + " properties");
            return;
        } else {
            for (const auto& [name, spec] : root["properties"].items()) {
                auto pr = canonicalise_property(name, spec, budget, errors);
                if (pr.info.has_default)
                    defaulted.push_back(name);
                if (pr.inline_required)
                    inline_required.push_back(name);
                props.push_back(std::move(pr.info));
                properties[name] = std::move(pr.canonical);
            }
        }
    }

    auto add_required = [&](const std::string& n) {
        if (std::find(required.begin(), required.end(), n) == required.end())
            required.push_back(n);
    };
    if (root.contains("required")) {
        if (!root["required"].is_array()) {
            errors.push_back("parameters root 'required' must be an array");
        } else {
            for (const auto& e : root["required"]) {
                if (!e.is_string()) {
                    errors.push_back("parameters root 'required' entries must be strings");
                    continue;
                }
                const auto& n = e.get_ref<const std::string&>();
                if (!valid_param_name(n))
                    errors.push_back("parameters root 'required' has an invalid parameter name");
                else if (!properties.contains(n))
                    errors.push_back("parameters root requires '" + n +
                                     "' which is not a declared parameter");
                else
                    add_required(n);
            }
        }
    }
    for (const auto& n : inline_required)
        add_required(n);

    // A declared default satisfies `required`: the name may be omitted.
    required.erase(std::remove_if(required.begin(), required.end(),
                                  [&](const std::string& n) {
                                      return std::find(defaulted.begin(), defaulted.end(), n) !=
                                             defaulted.end();
                                  }),
                   required.end());

    out = json::object();
    out["type"] = "object";
    out["properties"] = std::move(properties);
    if (!required.empty())
        out["required"] = required;
    out["additionalProperties"] = false;
}

// Rewrite one caller value toward the form the declared type accepts. Never reports a
// violation itself: a value that cannot be coerced is left as-is and the shared validator
// rejects it with its own reason.
void coerce(Kind kind, json& v) {
    switch (kind) {
    case Kind::kInteger:
        if (v.is_string())
            if (auto n = parse_decimal_int(v.get_ref<const std::string&>()))
                v = *n;
        break;
    case Kind::kBoolean:
        if (v.is_string()) {
            const auto& s = v.get_ref<const std::string&>();
            if (s == "true")
                v = true;
            else if (s == "false")
                v = false;
        }
        break;
    case Kind::kString:
        // Matches the route's `v.dump()` stringification of typed JSON.
        if (v.is_boolean() || v.is_number_integer() ||
            (v.is_number_float() && std::isfinite(v.get<double>())))
            v = v.dump();
        break;
    case Kind::kArray:
        break;
    }
}

// Server-authored reasons (fixed text: never the value, never the pattern).
constexpr const char* kNulReason = "string contains a NUL character";
constexpr const char* kTooLongReason =
    "string is longer than the server limit of 65536 bytes for a parameter with a pattern";
constexpr const char* kWorkReason =
    "string values matched against patterns or enum lists exceed the server's matching "
    "budget";
static_assert(kMaxPatternMatchedStringBytes == 65536,
              "kTooLongReason names the limit as text: keep them in step");

// The pre-validation guards for ONE string: a caller value in check(), or a schema-authored
// default at prepare time. `work` accumulates (bytes + 1) x program size; the +1 is the cost
// of starting a match (an empty string is not free). A string compared against an enum is
// charged `enum_members` more units, since the shared validator walks the member list.
// Returns the fixed reason, or nullptr when the string passes. It returns a reason, not a
// violation, so the (allocating) path is built only when there IS a violation.
const char* guard_string(const std::string& s, bool has_pattern, std::size_t program,
                         std::size_t enum_members, std::uint64_t& work) {
    if (s.find('\0') != std::string::npos)
        return kNulReason;
    if (!has_pattern && enum_members == 0)
        return nullptr;
    if (has_pattern) {
        if (s.size() > kMaxPatternMatchedStringBytes)
            return kTooLongReason;
        // s.size() <= 64 KiB and program <= 32768 + 65536: the product fits in 64 bits.
        work += (static_cast<std::uint64_t>(s.size()) + 1) * std::max<std::size_t>(program, 1);
    }
    work += enum_members;
    return work > kMaxPatternMatchWork ? kWorkReason : nullptr;
}

// Guards for one declared property's value (a caller value or a default), before the shared
// validator (and so before any pattern) runs. Only strings, and string elements of an array,
// are inspected; every other shape is left to the shared validator.
std::optional<mcp::SchemaViolation> guard_property(const PropInfo& p, const json& v,
                                                   std::uint64_t& work) {
    if (v.is_string()) {
        if (const char* reason = guard_string(v.get_ref<const std::string&>(), p.has_pattern,
                                              p.pattern_prog, p.enum_members, work))
            return mcp::SchemaViolation{"/" + p.name, reason};
        return std::nullopt;
    }
    if (p.kind == Kind::kArray && v.is_array()) {
        std::size_t index = 0;
        for (const auto& element : v) {
            if (element.is_string())
                if (const char* reason =
                        guard_string(element.get_ref<const std::string&>(), p.items_has_pattern,
                                     p.items_pattern_prog, p.items_enum_members, work))
                    return mcp::SchemaViolation{"/" + p.name + "/" + std::to_string(index),
                                                reason};
            ++index;
        }
    }
    return std::nullopt;
}

}  // namespace

struct ParamValidator::Impl {
    // nullopt = ABSENT (nothing declared).
    std::optional<mcp::CompiledInputSchema> schema;
    std::vector<PropInfo> props;
    std::size_t retained_bytes = 0;  // see estimated_retained_bytes(); 0 when absent
};

ParamValidator::ParamValidator(std::unique_ptr<const Impl> impl) : impl_(std::move(impl)) {}
ParamValidator::ParamValidator(ParamValidator&&) noexcept = default;
ParamValidator& ParamValidator::operator=(ParamValidator&&) noexcept = default;
ParamValidator::~ParamValidator() = default;

bool ParamValidator::absent() const noexcept {
    return impl_ && !impl_->schema;
}

std::size_t ParamValidator::estimated_retained_bytes() const noexcept {
    return impl_ ? impl_->retained_bytes : 0;
}

std::optional<mcp::SchemaViolation> ParamValidator::check(const json& params) const {
    if (!impl_)  // moved-from: never a silent pass
        return mcp::SchemaViolation{"", "validator unavailable"};
    if (!impl_->schema)
        return std::nullopt;
    if (!params.is_null() && !params.is_object())
        return mcp::SchemaViolation{"", "params must be an object"};

    // Copy ONLY the declared properties (coerced). An undeclared key is detected by count and
    // represented by the sentinel key "*" (never a legal parameter name), which the shared
    // validator reports as "/*" after every declared property.
    json subset = json::object();
    std::size_t present = 0;
    std::uint64_t work = 0;
    if (params.is_object()) {
        for (const auto& p : impl_->props) {
            const auto it = params.find(p.name);
            if (it == params.end())
                continue;
            ++present;
            if (auto violation = guard_property(p, *it, work))
                return violation;
            json value = *it;
            coerce(p.kind, value);
            subset.emplace(p.name, std::move(value));
        }
        if (params.size() > present)
            subset["*"] = true;
    }
    return impl_->schema->validate(subset);
}

namespace {

// Everything prepare_param_validator() does before it compiles the schema: the size, depth,
// parse and shape limits, then canonicalise_root(). nullopt = nothing stored (empty text or
// `{}`). `props` receives the per-property facts check() needs; `budget.compile` says whether
// user patterns are compiled and sized (enforcement) or left alone (canonicalise_param_schema).
std::expected<std::optional<json>, std::vector<std::string>>
canonicalise_stored(std::string_view stored_schema_json, PatternBudget& budget,
                    std::vector<PropInfo>& props) {
    std::vector<std::string> errors;

    // Size first, on the RAW text, before any trim/scan/parse.
    if (stored_schema_json.size() > kMaxParameterSchemaBytes) {
        errors.push_back("stored parameter schema is larger than " +
                         std::to_string(kMaxParameterSchemaBytes) + " bytes");
        return std::unexpected(std::move(errors));
    }

    const auto text = trim(stored_schema_json);
    if (text.empty())
        return std::nullopt;  // absent

    if (mcp::json_exceeds_depth(text, kMaxStoredSchemaDepth)) {
        errors.emplace_back("stored parameter schema nests deeper than " +
                            std::to_string(kMaxStoredSchemaDepth) + " levels");
        return std::unexpected(std::move(errors));
    }
    const auto parsed = json::parse(text, nullptr, /*allow_exceptions=*/false);
    if (parsed.is_discarded()) {
        errors.emplace_back("stored parameter schema is not valid JSON");
        return std::unexpected(std::move(errors));
    }
    if (!parsed.is_object()) {
        errors.emplace_back("stored parameter schema is not a JSON object");
        return std::unexpected(std::move(errors));
    }
    if (parsed.empty())
        return std::nullopt;  // `{}`: absent
    // Any other object is canonicalised; one without a root `type` is an error there (a
    // truncated schema must not silently skip validation).

    json canonical;
    canonicalise_root(parsed, canonical, props, budget, errors);
    if (!errors.empty())
        return std::unexpected(std::move(errors));
    return std::optional<json>(std::move(canonical));
}

}  // namespace

std::expected<std::optional<json>, std::vector<std::string>>
canonicalise_param_schema(std::string_view stored_schema_json) {
    PatternBudget budget;
    budget.compile = false;
    std::vector<PropInfo> props;
    return canonicalise_stored(stored_schema_json, budget, props);
}

std::expected<ParamValidator, std::vector<std::string>>
prepare_param_validator(std::string_view stored_schema_json) {
    std::vector<std::string> errors;
    auto impl = std::make_unique<ParamValidator::Impl>();

    PatternBudget budget;
    auto stored = canonicalise_stored(stored_schema_json, budget, impl->props);
    if (!stored)
        return std::unexpected(std::move(stored.error()));
    if (!*stored)
        return ParamValidator(std::move(impl));  // absent
    json canonical = std::move(**stored);

    auto compiled = mcp::compile_input_schema(canonical.dump());
    if (!compiled)
        return std::unexpected(std::move(compiled.error()));

    // Each declared default must satisfy its OWN property, validated alone (a one-property
    // schema, so another required parameter cannot mask it) after the coercion check()
    // applies. A default is author text matched against its pattern, so it goes through the
    // same guard_property() a caller value does, with ONE work budget shared by every default
    // of the schema. The failure reason is not reported: it could carry the default's value.
    std::uint64_t default_work = 0;
    for (const auto& p : impl->props) {
        if (!p.has_default)
            continue;
        const json& prop = canonical["properties"][p.name];
        if (const auto guarded = guard_property(p, prop["default"], default_work)) {
            errors.push_back("parameter '" + p.name + "': 'default' is not accepted: " +
                             guarded->reason);
            continue;
        }
        json solo = {{"type", "object"},
                     {"properties", json::object({{p.name, prop}})},
                     {"additionalProperties", false}};
        auto solo_compiled = mcp::compile_input_schema(solo.dump());
        if (!solo_compiled) {
            errors.push_back("parameter '" + p.name + "': 'default' could not be checked");
            continue;
        }
        json value = json::object();
        value[p.name] = prop["default"];
        coerce(p.kind, value[p.name]);
        if (solo_compiled->validate(value))
            errors.push_back("parameter '" + p.name +
                             "': 'default' does not satisfy the parameter's own type and "
                             "constraints");
    }
    if (!errors.empty())
        return std::unexpected(std::move(errors));

    // Every pattern in `props` (a user pattern, or the fixed datetime/guid one) is written into
    // the canonical schema and compiled by compile_input_schema, one RE2 per pattern; every
    // enum member is copied into the compiled schema as a JSON value.
    std::size_t patterns = 0;
    std::size_t enum_members = 0;
    for (const auto& p : impl->props) {
        patterns += static_cast<std::size_t>(p.has_pattern) +
                    static_cast<std::size_t>(p.items_has_pattern);
        enum_members += p.enum_members + p.items_enum_members;
    }
    impl->retained_bytes = kParamValidatorFixedBytes +
                           impl->props.size() * kParamValidatorPerPropertyBytes +
                           enum_members * kParamValidatorPerEnumMemberBytes +
                           trim(stored_schema_json).size() +
                           patterns * static_cast<std::size_t>(mcp::kPatternMaxMem);

    impl->schema.emplace(std::move(*compiled));
    return ParamValidator(std::move(impl));
}

ParamValidatorCache::ParamValidatorCache(std::size_t max_entries, std::size_t max_bytes,
                                         std::size_t max_entry_bytes)
    : max_entries_(max_entries == 0 ? 1 : max_entries), max_bytes_(max_bytes),
      max_entry_bytes_(max_entry_bytes) {}

std::size_t ParamValidatorCache::size() const {
    std::lock_guard lk(mu_);
    return lru_.size();
}

std::size_t ParamValidatorCache::bytes() const {
    std::lock_guard lk(mu_);
    return total_bytes_;
}

ParamValidatorCache::Result ParamValidatorCache::get(const std::string& definition_id,
                                                     const std::string& stored_schema) {
    const auto build = [&]() -> Result {
        auto prepared = prepare_param_validator(stored_schema);
        if (!prepared)
            return std::unexpected(std::move(prepared.error()));
        return std::make_shared<const ParamValidator>(std::move(*prepared));
    };

    // Over the size cap: the prepare error, before any hashing; never cached.
    std::string key;
    if (stored_schema.size() <= kMaxParameterSchemaBytes) {
        try {
            key = auth::AuthManager::sha256_hex(stored_schema) + ':' +
                  std::to_string(stored_schema.size()) + ':' + definition_id;
        } catch (const std::exception&) {
            key.clear();  // digest unavailable: compile without caching
        }
    }
    if (key.empty())
        return build();

    {
        std::lock_guard lk(mu_);
        if (auto it = index_.find(key); it != index_.end()) {
            lru_.splice(lru_.begin(), lru_, it->second);
            return it->second->validator;
        }
    }
    Result result = build();  // outside the lock
    if (!result || (*result)->absent())
        return result;
    // An entry heavier than the whole budget, or than the per-entry cap, is handed back but
    // never retained: admitting it would evict most of the other entries in one insert.
    const std::size_t weight = (*result)->estimated_retained_bytes();
    if (weight > max_bytes_ || weight > max_entry_bytes_)
        return result;
    try {
        std::lock_guard lk(mu_);
        if (!index_.contains(key)) {  // another thread may have inserted it meanwhile
            lru_.push_front(Entry{key, *result, weight});
            try {
                index_.emplace(key, lru_.begin());
            } catch (...) {
                lru_.pop_front();
                throw;
            }
            total_bytes_ += weight;
            // The new entry is at the front and fits alone, so this loop ends before it.
            while (lru_.size() > max_entries_ || total_bytes_ > max_bytes_) {
                total_bytes_ -= lru_.back().weight;
                index_.erase(lru_.back().key);
                lru_.pop_back();
            }
        }
    } catch (...) {
        // Caching is an optimisation: an allocation or lock failure leaves the cache usable.
    }
    return result;
}

}  // namespace yuzu::server::instr
