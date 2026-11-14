#include "instruction_definition_model.hpp"

#include "instruction_execute.hpp" // bounded_definition_id for the delete pre-image
#include "sensitive_instruction_params.hpp"
#include "sha256_hex.hpp"
#include "store_errors.hpp"
#include "web_utils.hpp" // flatten_audit_text

#include <yuzu/log_token.hpp>

#include <array>
#include <cctype>
#include <limits>

namespace yuzu::server {

nlohmann::json instruction_definition_row_json(const InstructionDefinition& d) {
    nlohmann::json j;
    j["id"] = d.id;
    j["name"] = d.name;
    j["version"] = d.version;
    j["type"] = d.type;
    j["plugin"] = d.plugin;
    j["action"] = d.action;
    j["description"] = d.description;
    j["enabled"] = d.enabled;
    j["instruction_set_id"] = d.instruction_set_id;
    j["created_at"] = d.created_at;
    j["updated_at"] = d.updated_at;
    return j;
}

nlohmann::json instruction_definition_detail_json(const InstructionDefinition& d) {
    nlohmann::json j = instruction_definition_row_json(d);
    j["gather_ttl_seconds"] = d.gather_ttl_seconds;
    j["response_ttl_days"] = d.response_ttl_days;
    j["created_by"] = d.created_by;
    j["approval_mode"] = d.approval_mode;
    j["parameter_schema"] = d.parameter_schema;
    j["result_schema"] = d.result_schema;
    j["yaml_source"] = d.yaml_source;
    // Parameter names a client must treat as write-only (password input, never echoed or
    // stored in history): the one shared list, so a dispatch form cannot keep its own copy.
    auto secrets = nlohmann::json::array();
    for (auto key : kRedactedInstructionParamKeys)
        secrets.push_back(std::string(key));
    j["secret_params"] = std::move(secrets);
    return j;
}

nlohmann::json instruction_definition_export_json(const InstructionDefinition& d) {
    nlohmann::json j = instruction_definition_detail_json(d);
    j.erase("secret_params"); // a client hint, not part of the exported definition
    j["concurrency_mode"] = d.concurrency_mode;
    j["platforms"] = d.platforms;
    j["min_agent_version"] = d.min_agent_version;
    j["required_plugins"] = d.required_plugins;
    j["readable_payload"] = d.readable_payload;
    j["visualization_spec"] = d.visualization_spec;
    j["response_templates_spec"] = d.response_templates_spec;
    return j;
}

// ---------------------------------------------------------------------------
// Request side (#2146 batch C)
// ---------------------------------------------------------------------------

namespace {

constexpr std::array<std::string_view, 12> kCreateKeys = {
    "id",     "name",        "version",            "type",
    "plugin", "action",      "description",        "enabled",
    "instruction_set_id", "gather_ttl_seconds", "response_ttl_days", "approval_mode"};

bool is_create_key(std::string_view k) {
    for (const auto key : kCreateKeys)
        if (key == k)
            return true;
    return false;
}

constexpr const char kFieldList[] =
    "allowed fields: id, name, version, type, plugin, action, description, enabled, "
    "instruction_set_id, gather_ttl_seconds, response_ttl_days, approval_mode";

bool read_string(const nlohmann::json& v, std::string& out) {
    if (!v.is_string())
        return false;
    out = v.get<std::string>();
    return true;
}

/// An integer in [lo, hi]; a float, string, bool or out-of-range value is a refusal.
bool read_int_in_range(const nlohmann::json& v, std::int64_t lo, std::int64_t hi,
                       std::int64_t& out) {
    if (!v.is_number_integer())
        return false;
    if (v.is_number_unsigned()) {
        const auto u = v.get<std::uint64_t>();
        if (u > static_cast<std::uint64_t>(hi))
            return false;
        out = static_cast<std::int64_t>(u);
    } else {
        out = v.get<std::int64_t>();
    }
    return out >= lo && out <= hi;
}

void lowercase_ascii(std::string& s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
}

bool valid_approval_mode(const std::string& m) {
    return m == "auto" || m == "role-gated" || m == "always";
}

/// Applies every present create-set key onto `def`. `allow_id` is false for the update body.
/// Returns the refusal text or nullopt.
std::optional<std::string> apply_definition_fields(const nlohmann::json& body, bool allow_id,
                                                   InstructionDefinition& def) {
    for (const auto& [key, v] : body.items()) {
        if (!is_create_key(key) || (!allow_id && key == "id"))
            return std::string("unknown field in request body; ") + kFieldList +
                   (allow_id ? "" : " (id is taken from the path and cannot be changed)");
        if (key == "id") {
            if (!read_string(v, def.id))
                return "id must be a string";
        } else if (key == "name") {
            if (!read_string(v, def.name))
                return "name must be a string";
            if (def.name.empty() || def.name.size() > kMaxDefinitionNameLen)
                return "name must be 1 to " + std::to_string(kMaxDefinitionNameLen) +
                       " characters";
        } else if (key == "version") {
            if (!read_string(v, def.version))
                return "version must be a string";
            if (def.version.empty() || def.version.size() > kMaxDefinitionVersionLen)
                return "version must be 1 to " + std::to_string(kMaxDefinitionVersionLen) +
                       " characters";
        } else if (key == "type") {
            if (!read_string(v, def.type))
                return "type must be a string";
            if (!is_valid_definition_type(def.type))
                return "type must be one of: question, action";
        } else if (key == "plugin") {
            if (!read_string(v, def.plugin))
                return "plugin must be a string";
            // A present key must carry a usable plugin: an empty value would blank the column
            // (update_definition re-checks nothing about plugin), and create needs one anyway.
            if (auto err = check_dispatch_identifier("plugin", def.plugin))
                return err;
        } else if (key == "action") {
            if (!read_string(v, def.action))
                return "action must be a string";
            // Agent plugins match the action case-sensitively: lowercase it, as the legacy routes do.
            lowercase_ascii(def.action);
            if (!def.action.empty())
                if (auto err = check_dispatch_identifier("action", def.action))
                    return err;
        } else if (key == "description") {
            if (!read_string(v, def.description))
                return "description must be a string";
            if (def.description.size() > kMaxDefinitionDescriptionLen)
                return "description must be at most " +
                       std::to_string(kMaxDefinitionDescriptionLen) + " bytes";
        } else if (key == "enabled") {
            if (!v.is_boolean())
                return "enabled must be a boolean";
            def.enabled = v.get<bool>();
        } else if (key == "instruction_set_id") {
            if (!read_string(v, def.instruction_set_id))
                return "instruction_set_id must be a string";
            if (def.instruction_set_id.size() > kMaxDefinitionInstructionSetIdLen)
                return "instruction_set_id must be at most " +
                       std::to_string(kMaxDefinitionInstructionSetIdLen) + " characters";
        } else if (key == "gather_ttl_seconds") {
            std::int64_t n = 0;
            if (!read_int_in_range(v, 1, kMaxDefinitionGatherTtlSeconds, n))
                return "gather_ttl_seconds must be an integer between 1 and " +
                       std::to_string(kMaxDefinitionGatherTtlSeconds);
            def.gather_ttl_seconds = static_cast<int>(n);
        } else if (key == "response_ttl_days") {
            std::int64_t n = 0;
            if (!read_int_in_range(v, 1, kMaxDefinitionResponseTtlDays, n))
                return "response_ttl_days must be an integer between 1 and " +
                       std::to_string(kMaxDefinitionResponseTtlDays);
            def.response_ttl_days = static_cast<int>(n);
        } else { // approval_mode: is_create_key admitted nothing else
            std::string mode;
            if (!read_string(v, mode))
                return "approval_mode must be a string";
            if (!valid_approval_mode(mode))
                return "approval_mode must be one of: auto, role-gated, always";
            def.approval_mode = std::move(mode);
        }
    }
    return std::nullopt;
}

} // namespace

std::optional<std::string> check_dispatch_identifier(std::string_view field,
                                                     std::string_view value) {
    if (value.empty() || value.size() > kMaxDefinitionDispatchIdentifierLen)
        return std::string(field) + " must be 1 to " +
               std::to_string(kMaxDefinitionDispatchIdentifierLen) + " characters";
    for (const char ch : value) {
        const bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                        (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-';
        if (!ok)
            return std::string(field) + " may only contain letters, digits, '_', '.' and '-'";
    }
    return std::nullopt;
}

std::expected<InstructionDefinition, std::string>
build_definition_from_create_body(const nlohmann::json& body, std::string_view created_by) {
    if (!body.is_object())
        return std::unexpected(std::string("request body must be a JSON object"));
    InstructionDefinition def;
    // The legacy create defaults (instruction_routes.cpp), applied before the body so an absent
    // key keeps them.
    def.version = "1.0";
    def.enabled = true;
    def.gather_ttl_seconds = 300;
    def.response_ttl_days = 90;
    def.approval_mode = "auto";
    if (auto err = apply_definition_fields(body, /*allow_id=*/true, def))
        return std::unexpected(std::move(*err));
    def.created_by = std::string(created_by);
    return def;
}

std::expected<DefinitionUpdateRequest, std::string>
apply_definition_update_body(const nlohmann::json& body, InstructionDefinition& def) {
    if (!body.is_object())
        return std::unexpected(std::string("request body must be a JSON object"));
    DefinitionUpdateRequest req;
    // `expected_updated_at` is a request control, not a column: read it out, then apply the rest.
    nlohmann::json fields = nlohmann::json::object();
    for (const auto& [key, v] : body.items()) {
        if (key == "expected_updated_at") {
            std::int64_t n = 0;
            if (!read_int_in_range(v, 0, std::numeric_limits<std::int64_t>::max(), n))
                return std::unexpected(
                    std::string("expected_updated_at must be a non-negative integer"));
            req.expected_updated_at = n;
        } else {
            fields[key] = v;
        }
    }
    if (auto err = apply_definition_fields(fields, /*allow_id=*/false, def))
        return std::unexpected(std::move(*err));
    return req;
}

bool clear_stale_yaml_source(const InstructionDefinition& before, InstructionDefinition& def) {
    if (before.yaml_source.empty())
        return false;
    // The columns `merge_yaml_into_stored` takes from the YAML: plugin and action always, name
    // always, approval_mode / concurrency_mode / version / type / description when the YAML states
    // them. `enabled` is not merged, so it is not here.
    const bool stale = before.plugin != def.plugin || before.action != def.action ||
                       before.approval_mode != def.approval_mode ||
                       before.concurrency_mode != def.concurrency_mode ||
                       before.name != def.name || before.description != def.description ||
                       before.version != def.version || before.type != def.type;
    if (!stale)
        return false;
    def.yaml_source.clear();
    return true;
}

std::string describe_dispatch_binding_change(const InstructionDefinition& before,
                                             const InstructionDefinition& after) {
    std::string out;
    // Free-text values (the legacy PUT, which does not bound them, can store plugin / action / concurrency_mode of any length) are
    // bounded for the detail, but COMPARED whole: two values equal in their first 128 bytes are
    // still a change.
    const auto shown = [](const std::string& v) {
        return ::yuzu::log_token(instruction_execute::bounded_definition_id(v));
    };
    const auto note = [&](std::string_view name, const std::string& was, const std::string& now) {
        if (was == now)
            return;
        if (!out.empty())
            out += "; ";
        out += std::string(name) + ": " + shown(was) + " -> " + shown(now);
    };
    note("plugin", before.plugin, after.plugin);
    note("action", before.action, after.action);
    note("approval_mode", before.approval_mode, after.approval_mode);
    note("concurrency_mode", before.concurrency_mode, after.concurrency_mode);
    note("enabled", before.enabled ? "true" : "false", after.enabled ? "true" : "false");
    if (!before.yaml_source.empty() && after.yaml_source.empty()) {
        // The YAML was cleared because one of these changed (clear_stale_yaml_source), so name
        // which: they do not decide what the definition runs, so they are recorded only here. A
        // description can be long, so only its sizes are shown.
        note("name", before.name, after.name);
        note("version", before.version, after.version);
        note("type", before.type, after.type);
        if (before.description != after.description) {
            if (!out.empty())
                out += "; ";
            out += "description: changed " + std::to_string(before.description.size()) + " -> " +
                   std::to_string(after.description.size()) + " bytes";
        }
        if (!out.empty())
            out += "; ";
        out += "yaml_source cleared";
        // The cleared text is gone from the row: its size and digest let an auditor match the
        // event to a backup or an export. The digest is omitted if the provider fails.
        out += " yaml_source_bytes=" + std::to_string(before.yaml_source.size());
        if (const auto digest = ::yuzu::server::sha256_hex(before.yaml_source))
            out += " yaml_source_sha256=" + *digest;
    }
    return out;
}

std::string describe_deleted_definition(const InstructionDefinition& def) {
    const auto token = [](std::string_view v) {
        return ::yuzu::log_token(instruction_execute::bounded_definition_id(v));
    };
    return "name=" + token(def.name) + " plugin=" + token(def.plugin) +
           " action=" + token(def.action) + " approval_mode=" + token(def.approval_mode) +
           " concurrency_mode=" + token(def.concurrency_mode) +
           " enabled=" + (def.enabled ? "true" : "false");
}

std::expected<InstructionSet, std::string>
build_instruction_set_from_body(const nlohmann::json& body, std::string_view created_by) {
    if (!body.is_object())
        return std::unexpected(std::string("request body must be a JSON object"));
    InstructionSet s;
    for (const auto& [key, v] : body.items()) {
        if (key == "name") {
            if (!read_string(v, s.name))
                return std::unexpected(std::string("name must be a string"));
        } else if (key == "description") {
            if (!read_string(v, s.description))
                return std::unexpected(std::string("description must be a string"));
        } else {
            return std::unexpected(
                std::string("unknown field in request body; allowed fields: name, description"));
        }
    }
    s.created_by = std::string(created_by);
    return s;
}

std::expected<YamlSaveRequest, std::string> parse_yaml_save_body(const nlohmann::json& body) {
    if (!body.is_object())
        return std::unexpected(std::string("request body must be a JSON object"));
    YamlSaveRequest out;
    for (const auto& [key, v] : body.items()) {
        if (key == "yaml_source") {
            if (!read_string(v, out.yaml_source))
                return std::unexpected(std::string("yaml_source must be a string"));
        } else if (key == "id") {
            if (!read_string(v, out.id))
                return std::unexpected(std::string("id must be a string"));
        } else if (key == "updated_at") {
            std::int64_t n = 0;
            if (!read_int_in_range(v, 0, std::numeric_limits<std::int64_t>::max(), n))
                return std::unexpected(std::string("updated_at must be a non-negative integer"));
            out.expected_updated_at = n;
        } else {
            return std::unexpected(std::string(
                "unknown field in request body; allowed fields: yaml_source, id, updated_at"));
        }
    }
    if (out.yaml_source.empty())
        return std::unexpected(std::string("yaml_source is required"));
    return out;
}

std::expected<std::string, std::string> parse_yaml_validate_body(const nlohmann::json& body) {
    if (!body.is_object())
        return std::unexpected(std::string("request body must be a JSON object"));
    std::string yaml_source;
    bool seen = false;
    for (const auto& [key, v] : body.items()) {
        if (key != "yaml_source")
            return std::unexpected(
                std::string("unknown field in request body; allowed fields: yaml_source"));
        if (!read_string(v, yaml_source))
            return std::unexpected(std::string("yaml_source must be a string"));
        seen = true;
    }
    if (!seen)
        return std::unexpected(std::string("yaml_source is required"));
    return yaml_source;
}

std::optional<std::string>
check_yaml_dispatch_fields(const instruction_yaml::DefinitionFields& fields) {
    if (!fields.plugin.empty())
        if (auto err = check_dispatch_identifier("plugin", fields.plugin))
            return err;
    if (!fields.action.empty())
        if (auto err = check_dispatch_identifier("action", fields.action))
            return err;
    return std::nullopt;
}

std::vector<std::string> check_yaml_field_bounds(const instruction_yaml::DefinitionFields& fields) {
    std::vector<std::string> out;
    if (fields.name.size() > kMaxDefinitionNameLen)
        out.push_back("name must be 1 to " + std::to_string(kMaxDefinitionNameLen) + " characters");
    if (fields.version.size() > kMaxDefinitionVersionLen)
        out.push_back("version must be 1 to " + std::to_string(kMaxDefinitionVersionLen) +
                      " characters");
    // The bundled content carries descriptions past the builders' 512 (91 of the 296; the longest
    // is about 4.9 KB), so the YAML path takes the import's wider bound.
    if (fields.description.size() > kMaxDefinitionImportDescriptionLen)
        out.push_back("description must be at most " +
                      std::to_string(kMaxDefinitionImportDescriptionLen) + " bytes");
    return out;
}

std::optional<std::string> yaml_source_byte_refusal(const std::string& yaml_source) {
    // The same checks, in the same order and with the same texts, as validate_definition_yaml
    // (instruction_yaml.cpp), which a source refused here also reaches through validate_yaml_source.
    if (yaml_source.find('\0') != std::string::npos)
        return std::string("YAML source contains a NUL byte");
    if (yaml_source.size() > kMaxDefinitionYamlSourceBytes)
        return std::string("yaml_source too large (max 1MB)");
    return std::nullopt;
}

std::vector<std::string> validate_yaml_for_authoring(const std::string& yaml_source) {
    auto errors = validate_yaml_source(yaml_source);
    // A source refused on its bytes (NUL, over the size cap) is never parsed: parsing a document
    // that is already refused is pure CPU a read-only caller could drive (4 MiB of newlines cost
    // ~376 ms per request). validate_yaml_source above reports it with one error.
    if (yaml_source_byte_refusal(yaml_source))
        return errors;
    // parse_definition_yaml is total (it never throws and an unparseable document yields empty
    // fields), so this is safe to run on a document the validator refused for another reason.
    const auto fields = instruction_yaml::parse_definition_yaml(yaml_source);
    if (auto err = check_yaml_dispatch_fields(fields))
        errors.push_back(std::move(*err));
    for (auto& err : check_yaml_field_bounds(fields))
        errors.push_back(std::move(err));
    return errors;
}

std::string audit_store_error_text(const std::string& err) {
    constexpr std::string_view kPrefix = "invalid approval_mode: ";
    constexpr std::string_view kSuffix = " (must be auto, role-gated, or always)";
    constexpr std::size_t kMax = 200; // longest store text copied into an audit detail
    const std::string_view text = err;
    if (text.size() >= kPrefix.size() + kSuffix.size() && text.starts_with(kPrefix) &&
        text.ends_with(kSuffix)) {
        const auto value =
            text.substr(kPrefix.size(), text.size() - kPrefix.size() - kSuffix.size());
        return std::string(kPrefix) + ::yuzu::log_token(instruction_execute::bounded_definition_id(value)) +
               std::string(kSuffix);
    }
    std::string flat = flatten_audit_text(text.substr(0, kMax));
    if (instruction_execute::definition_id_needs_audit_fold(flat))
        flat = ::yuzu::log_token(flat);
    return flat;
}

std::optional<std::string> check_yaml_update_id(const instruction_yaml::DefinitionFields& fields,
                                                std::string_view def_id) {
    if (!fields.id.empty() && fields.id != def_id)
        return std::string("yaml metadata.id does not match the definition being updated; "
                           "correct or remove metadata.id");
    return std::nullopt;
}

StoreFault classify_store_error(const std::string& err) {
    if (err.rfind(kInstructionStoreDbErrorPrefix, 0) == 0)
        return StoreFault::kDb;
    if (err.rfind(kNotFoundPrefix, 0) == 0)
        return StoreFault::kNotFound;
    if (is_conflict_error(err))
        return StoreFault::kConflict;
    return StoreFault::kInvalid;
}

InstructionDefinition definition_from_yaml_fields(const instruction_yaml::DefinitionFields& fields,
                                                  const std::string& yaml_source,
                                                  std::string_view created_by) {
    InstructionDefinition def;
    def.id = fields.id; // honoured (the store 409s on conflict); empty -> store-generated
    def.name = fields.name;
    def.version = fields.version.empty() ? "1.0.0" : fields.version;
    def.plugin = fields.plugin;
    def.action = fields.action; // lowercased by the parser
    def.type = fields.type.empty() ? "question" : fields.type;
    def.description = fields.description;
    def.concurrency_mode = fields.concurrency.empty() ? "per-device" : fields.concurrency;
    def.approval_mode = fields.approval.empty() ? "auto" : fields.approval;
    def.yaml_source = yaml_source;
    def.created_by = std::string(created_by);
    def.enabled = true;
    return def;
}

} // namespace yuzu::server
