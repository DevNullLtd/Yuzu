/// @file guardian_schema_registry.cpp — see guardian_schema_registry.hpp.

#include "guardian_schema_registry.hpp"

#include "guardian_resilience_schema.hpp"

#include <yuzu/guardian_file_hash_limits.hpp> // kMaxFileHashBytes (#2233 item 6)

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::guardian {
namespace {

using nlohmann::json;

// Single source for the registry hive / value-type enums (H2). These MUST mirror
// exactly what the agent's RegistryGuard parses (`registry_support::kHives` /
// `kValueTypes` in guard_registry.hpp): parse_hive() maps these four hives, and
// read_value()/write_value() decode these four value types. HKCC, REG_BINARY and
// REG_MULTI_SZ were previously advertised here but the agent decodes none of them
// — a guard authored against one read back as "<unsupported-type>" forever
// (perpetual false drift / remediation.failed). Drives the published enum, the
// authoring validator, and the cross-check test (contract G9 drift guard).
constexpr std::string_view kRegistryHives[] = {"HKLM", "HKCU", "HKCR", "HKU"};
constexpr std::string_view kRegistryValueTypes[] = {"REG_DWORD", "REG_QWORD", "REG_SZ",
                                                    "REG_EXPAND_SZ"};

// Single source for the service run-state tokens (H2). These MUST mirror exactly
// what the agent's ServiceGuard arms (`service_support::kStates` in
// guard_service.hpp): each `S` here maps to a `service-<S>` assertion below and to
// the agent's service spark branch in guardian_engine.cpp. `service-disabled`
// (start-type config) is intentionally NOT here until the agent decodes it — it is
// registry-expressible today via the Services\<name>\Start DWORD. Drives the
// authoring validator and the schema↔handler cross-check test (contract G9).
constexpr std::string_view kServiceStates[] = {"running", "stopped"};

json string_view_enum(const std::string_view* first, const std::string_view* last) {
    json arr = json::array();
    for (const std::string_view* it = first; it != last; ++it)
        arr.push_back(std::string(*it));
    return arr;
}

// A complete spec-block schema: {type: {const}, params: <params schema>}.
json block_schema(const char* type, const char* title, json params, bool params_required) {
    json props = {
        {"type", {{"const", type}}},
        {"params", std::move(params)},
    };
    json required = json::array({"type"});
    if (params_required)
        required.push_back("params");
    return json{
        {"title", title},
        {"type", "object"},
        {"properties", std::move(props)},
        {"required", std::move(required)},
        {"additionalProperties", false},
    };
}

// Assertion params for registry-value-equals (contract decision G4). `expected`
// is string-encoded per `value_type`; the discriminated subschemas below make the
// per-type encoding machine-discoverable rather than prose (decision 3).
json registry_value_equals_params() {
    json props = {
        {"hive",
         {{"type", "string"},
          {"enum", string_view_enum(std::begin(kRegistryHives), std::end(kRegistryHives))},
          {"description", "Registry hive."}}},
        {"key", {{"type", "string"}, {"description", "Key path under the hive, e.g. SOFTWARE\\\\YuzuTest."}}},
        {"value_name",
         {{"type", "string"}, {"description", "Value name; \"\" means the key's default value."}}},
        {"value_type",
         {{"type", "string"},
          {"enum",
           string_view_enum(std::begin(kRegistryValueTypes), std::end(kRegistryValueTypes))},
          {"description", "Registry value type; the comparison is type-aware (a type mismatch is drift)."}}},
        {"expected",
         {{"type", "string"},
          {"description", "Desired value, string-encoded per value_type: DWORD/QWORD decimal "
                          "(0x… accepted, canonical decimal); SZ/EXPAND_SZ literal."}}},
    };
    // Discriminated subschemas keyed on value_type (decision 3). Built explicitly
    // (not via nested brace-init) so the object/array shape is unambiguous.
    auto discriminator = [](json value_type_match, const char* expected_pattern) {
        json if_clause = json::object();
        if_clause["properties"]["value_type"] = std::move(value_type_match);
        json then_clause = json::object();
        then_clause["properties"]["expected"]["pattern"] = expected_pattern;
        json rule = json::object();
        rule["if"] = std::move(if_clause);
        rule["then"] = std::move(then_clause);
        return rule;
    };
    json discriminators = json::array();
    {
        json enum_match = json::object();
        enum_match["enum"] = json::array({"REG_DWORD", "REG_QWORD"});
        discriminators.push_back(discriminator(std::move(enum_match), "^(0x[0-9a-fA-F]+|[0-9]+)$"));
    }
    return json{
        {"type", "object"},
        {"properties", std::move(props)},
        {"required", json::array({"hive", "key", "value_type", "expected"})},
        {"allOf", std::move(discriminators)},
        {"additionalProperties", false},
    };
}

// registry-change spark: matched on `type` only. The watched key is derived from
// the assertion's hive/key, so the spark carries no required params today.
json registry_change_params() {
    return json{
        {"type", "object"},
        {"description", "No params: the registry watch target is taken from the assertion's hive/key."},
        {"properties", json::object()},
        {"additionalProperties", true},
    };
}

// file-change spark (Change B): matched on `type` only — the watched file is the
// assertion's `path`. Realtime via ReadDirectoryChangesW on the parent directory
// (Windows MVP; Linux inotify / macOS FSEvents later).
json file_change_params() {
    return json{
        {"type", "object"},
        {"description", "No params: the watch target is the assertion's `path`."},
        {"properties", json::object()},
        {"additionalProperties", true},
    };
}

// file-exists assertion: realtime detection of a file being created or deleted.
json file_exists_params() {
    json props = {
        {"path",
         {{"type", "string"},
          {"description", "Absolute path of the file to watch (canonicalised on the agent)."}}},
        {"expected",
         {{"type", "string"},
          {"enum", json::array({"present", "absent"})},
          {"default", "present"},
          {"description", "Desired state: present → drift when the file is deleted; absent → "
                          "tripwire, drift when the file is created."}}},
    };
    return json{
        {"type", "object"},
        {"properties", std::move(props)},
        {"required", json::array({"path"})},
        {"additionalProperties", false},
    };
}

// file-hash-equals assertion: realtime content-change detection. `expected_hash`
// is a 64-char lowercase SHA-256 hex (the pattern is the discriminated format
// check, mirroring registry value_type's encoding subschemas); empty = baseline
// captured on arm.
json file_hash_equals_params() {
    json props = {
        {"path", {{"type", "string"}, {"description", "Absolute path of the file to watch."}}},
        {"expected_hash",
         {{"type", "string"},
          {"pattern", "^([0-9a-fA-F]{64})?$"},
          {"description", "Known-good SHA-256 hex (64 chars). Empty → baseline captured on arm "
                          "(drift on any later content change)."}}},
        {"max_bytes",
         {{"type", json::array({"integer", "string"})},
          {"minimum", 1},
          {"maximum", yuzu::guardian::kMaxFileHashBytes},
          {"default", 67108864},
          {"description", "Hashing-DoS cap (bytes). A file larger than this reports <oversize> "
                          "rather than being hashed. A non-negative-integer value above the "
                          "maximum, in either JSON form, is rejected at authoring time; a "
                          "other numeric value (a float, or a negative number) is rejected as "
                          "malformed, the same as an unparseable string. A rule already stored "
                          "above the ceiling before this check existed is not retroactively "
                          "rejected - the agent silently clamps to the ceiling on arm, with a "
                          "warning re-logged on each arm/reconcile while it stays over the "
                          "ceiling."}}},
        {"settle_ms",
         {{"type", json::array({"integer", "string"})},
          {"minimum", 0},
          {"default", 750},
          {"description", "Quiescence window (ms) before hashing — coalesces mid-write "
                          "notifications so a partial write is not reported as drift."}}},
    };
    return json{
        {"type", "object"},
        {"properties", std::move(props)},
        {"required", json::array({"path"})},
        {"additionalProperties", false},
    };
}

// service-status-change spark (PR5): matched on `type` only — the watched service
// is the assertion's `service_name`, mirroring how registry-change derives its
// target from the assertion. No required params. Real-time on the agent via
// NotifyServiceStatusChange (Windows MVP).
json service_status_change_params() {
    return json{
        {"type", "object"},
        {"description", "No params: the watched service is the assertion's `service_name`."},
        {"properties", json::object()},
        {"additionalProperties", true},
    };
}

// service-running / service-stopped assertion params. The assertion TYPE encodes the
// desired run state; the only param is the SCM service (key) name. The pattern
// mirrors the agent's valid_service_name() (alphanumeric + . _ - @, 1..256) so a
// name the agent would reject cannot be authored.
json service_assertion_params() {
    json props = {
        {"service_name",
         {{"type", "string"},
          {"pattern", "^[A-Za-z0-9._@-]{1,256}$"},
          {"description", "SCM service (key) name, e.g. Spooler — NOT the display name."}}},
    };
    return json{
        {"type", "object"},
        {"properties", std::move(props)},
        {"required", json::array({"service_name"})},
        {"additionalProperties", false},
    };
}

json build_catalog() {
    json schemas = json::array();

    // {kind, type, json_schema} per G9 — the schema is NESTED under json_schema so
    // it keeps its own JSON-Schema "type":"object" (not overwritten by the
    // discriminator name) and the entry stays a well-formed catalog row.
    auto add = [&](const char* kind, const char* type_name, json schema) {
        json entry = json::object();
        entry["kind"] = kind;
        entry["type"] = type_name;
        entry["json_schema"] = std::move(schema);
        schemas.push_back(std::move(entry));
    };

    add("spark", "registry-change",
        block_schema("registry-change", "Registry change trigger", registry_change_params(),
                     /*params_required=*/false));
    add("spark", "file-change",
        block_schema("file-change", "File change trigger (realtime)", file_change_params(),
                     /*params_required=*/false));
    add("spark", "service-status-change",
        block_schema("service-status-change", "Service status change trigger (realtime)",
                     service_status_change_params(), /*params_required=*/false));
    add("assertion", "registry-value-equals",
        block_schema("registry-value-equals", "Registry value equals",
                     registry_value_equals_params(), /*params_required=*/true));
    add("assertion", "file-exists",
        block_schema("file-exists", "File exists / absent", file_exists_params(),
                     /*params_required=*/true));
    add("assertion", "file-hash-equals",
        block_schema("file-hash-equals", "File content matches a hash", file_hash_equals_params(),
                     /*params_required=*/true));
    // Service run-state assertions (PR5). The state is encoded in the assertion TYPE
    // (one per kServiceStates token); the only param is the service name. The
    // schema↔handler cross-check binds these to the agent's service_support::kStates.
    add("assertion", "service-running",
        block_schema("service-running", "Service must be running", service_assertion_params(),
                     /*params_required=*/true));
    add("assertion", "service-stopped",
        block_schema("service-stopped", "Service must be stopped", service_assertion_params(),
                     /*params_required=*/true));
    // Resilience policy lives in remediation.params for BOTH actions (it is read
    // for every guard); the mode/backoff/bounded params take effect only when the
    // guard actually enforces — event_debounce_ms applies in alert-only too. The
    // schema documents that via resilience_params_schema()'s descriptions.
    add("remediation", "alert-only",
        block_schema("alert-only", "Detect and alert (no write-back)", resilience_params_schema(),
                     /*params_required=*/false));
    add("remediation", "enforce",
        block_schema("enforce", "Detect and write the expected value back",
                     resilience_params_schema(), /*params_required=*/false));

    return json{
        {"version", 1},
        {"description",
         "Guardian Guard authoring schemas (contract G9). A Guard is three "
         "{type, params} blocks — spark, assertion, remediation — plus "
         "enabled/enforcement_mode/version. enforcement_mode (enforce|audit) is the "
         "master gate; remediation.type is the authored action."},
        {"schemas", std::move(schemas)},
    };
}

// FNV-1a 64-bit over the serialised catalog → a strong, content-derived ETag so a
// schema edit invalidates caches automatically (no manual version bump needed).
std::string content_etag(const std::string& body) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : body) {
        h ^= c;
        h *= 1099511628211ull;
    }
    char buf[19];
    int n = std::snprintf(buf, sizeof(buf), "\"%016llx\"", static_cast<unsigned long long>(h));
    return std::string(buf, static_cast<std::size_t>(n));
}

} // namespace

const SchemaCatalog& guardian_schema_catalog() {
    static const SchemaCatalog catalog = [] {
        SchemaCatalog c;
        c.json = build_catalog().dump();
        c.etag = content_etag(c.json);
        return c;
    }();
    return catalog;
}

const std::vector<std::string_view>& supported_registry_hives() {
    static const std::vector<std::string_view> v(std::begin(kRegistryHives),
                                                  std::end(kRegistryHives));
    return v;
}

const std::vector<std::string_view>& supported_registry_value_types() {
    static const std::vector<std::string_view> v(std::begin(kRegistryValueTypes),
                                                  std::end(kRegistryValueTypes));
    return v;
}

const std::vector<std::string_view>& supported_service_states() {
    static const std::vector<std::string_view> v(std::begin(kServiceStates),
                                                  std::end(kServiceStates));
    return v;
}

} // namespace yuzu::server::guardian
