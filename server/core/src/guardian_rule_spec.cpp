/// @file guardian_rule_spec.cpp — see guardian_rule_spec.hpp.

#include "guardian_rule_spec.hpp"

#include "guardian_resilience_schema.hpp"
#include "guardian_schema_registry.hpp" // supported_registry_hives / value_types

#include <yuzu/guardian_file_hash_limits.hpp> // kMaxFileHashBytes (#2233 item 6)

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The max_bytes-over-ceiling ResilienceParamError remediation text below hardcodes
// "1073741824 (1 GiB)" rather than building it from yuzu::guardian::kMaxFileHashBytes
// (cheaper than a std::to_string call on a validation hot path) - this assert is what
// keeps that hardcoded text honest if the constant ever moves.
static_assert(yuzu::guardian::kMaxFileHashBytes == 1073741824ull,
              "guardian_rule_spec.cpp's max_bytes ResilienceParamError text hardcodes "
              "this value - update both if kMaxFileHashBytes changes");

namespace yuzu::server::guardian {
namespace {

// ASCII-lowercase copy for case-insensitive registry matching — registry hives,
// keys and value-type tokens are case-insensitive on Windows.
std::string ascii_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool in_set(const std::vector<std::string_view>& set, const std::string& v) {
    return std::find(set.begin(), set.end(), v) != set.end();
}

// Whole-string non-negative integer? Rejects "123abc", "", "-1", "1.5" — mirrors
// the agent's hardened parse so the server boundary and the agent boundary agree
// on what a numeric param is (M1).
bool is_whole_u64(const std::string& s, std::uint64_t& out) {
    if (s.empty())
        return false;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    return ec == std::errc{} && p == s.data() + s.size();
}

std::string str_param(const nlohmann::json& params, const char* k) {
    if (params.contains(k) && params[k].is_string())
        return params[k].get<std::string>();
    return {};
}

// Validate the assertion params against the published supported sets (H2), the
// enforce-write dangerous-key denylist (H1, contract §6) and basic file-assertion
// sanity (M1) — lenient where the agent is lenient, fail-loud where a value would
// arm a confidently-wrong guard (perpetual false drift / remediation.failed).
std::optional<ResilienceParamError>
validate_assertion_params(const std::string& assertion_type, const nlohmann::json& assertion,
                          const std::string& enforcement_mode) {
    const nlohmann::json params =
        (assertion.contains("params") && assertion["params"].is_object())
            ? assertion["params"]
            : nlohmann::json::object();

    if (assertion_type == "registry-value-equals") {
        const std::string hive = str_param(params, "hive");
        const std::string key = str_param(params, "key");
        const std::string value_type = str_param(params, "value_type");
        if (key.empty())
            return ResilienceParamError{
                "registry assertion requires a non-empty 'key'",
                "set assertion.params.key to the subkey path under the hive"};
        if (!in_set(supported_registry_hives(), hive))
            return ResilienceParamError{
                "unsupported registry hive '" + hive + "'",
                "use a hive published by GET /api/v1/guaranteed-state/schemas "
                "(HKLM, HKCU, HKCR, HKU)"};
        if (!in_set(supported_registry_value_types(), value_type))
            return ResilienceParamError{
                "unsupported registry value_type '" + value_type + "'",
                "use a value type published by GET /api/v1/guaranteed-state/schemas "
                "(REG_DWORD, REG_QWORD, REG_SZ, REG_EXPAND_SZ)"};
        if (enforcement_mode == "enforce")
            if (std::string why = dangerous_enforce_registry_key(key); !why.empty())
                return ResilienceParamError{
                    "enforce-mode registry write to " + why + " is not permitted",
                    "author this Guard in audit mode (enforcement_mode=\"audit\") to observe "
                    "drift, or target a key outside the protected persistence / privilege set"};
        return std::nullopt;
    }

    if (assertion_type == "file-exists") {
        if (str_param(params, "path").empty())
            return ResilienceParamError{"file-exists assertion requires a non-empty 'path'",
                                        "set assertion.params.path to the absolute file path"};
        if (params.contains("expected") && params["expected"].is_string()) {
            const std::string e = params["expected"].get<std::string>();
            if (e != "present" && e != "absent")
                return ResilienceParamError{
                    "file-exists 'expected' must be 'present' or 'absent'",
                    "set assertion.params.expected to present or absent"};
        }
        return std::nullopt;
    }

    if (assertion_type == "file-hash-equals") {
        if (str_param(params, "path").empty())
            return ResilienceParamError{"file-hash-equals assertion requires a non-empty 'path'",
                                        "set assertion.params.path to the absolute file path"};
        const std::string h = str_param(params, "expected_hash");
        if (!h.empty() &&
            (h.size() != 64 ||
             !std::all_of(h.begin(), h.end(), [](unsigned char c) { return std::isxdigit(c); })))
            return ResilienceParamError{
                "expected_hash must be a 64-char SHA-256 hex digest (or empty)",
                "supply the 64-char hex digest, or leave it empty to baseline on arm"};
        // max_bytes / settle_ms are string-or-int on the wire; the pre-existing
        // (untouched-by-this-check) design only ever fully validated the string
        // form here, leaving an integer max_bytes to the agent's own bounded
        // parse. The #2233 item 6 ceiling check below applies to BOTH wire forms
        // (closing an asymmetry this PR itself would otherwise introduce - a
        // ceiling enforced for one JSON type and not the other is not really a
        // ceiling): a JSON-string value is still fully validated (positive
        // integer + ceiling); a JSON-number value is now ALSO shape-validated
        // (must be a non-negative integer literal, matching the string form's
        // own "positive integer" bar) before the ceiling check - a JSON float,
        // negative number, or uint64-overflow literal was previously accepted
        // outright and then silently discarded server- AND agent-side in favour
        // of the 64 MiB default (Gate 8 unhappy-path/security-guardian/
        // cpp-expert/quality-engineer, 4 independent reporters: not a ceiling
        // bypass - agents/core/src/guardian_engine.cpp's aparam_u64 requires a
        // whole-string integer parse and falls back to the default for
        // anything else - but a genuinely unlogged state-divergence bug for an
        // operator authoring a deliberately strict, well-under-ceiling cap).
        // Zero-check for the numeric form stays deferred to the agent, matching
        // this file's pre-existing design for that wire form - only shape +
        // ceiling are closed for both forms now.
        std::uint64_t n = 0;
        if (params.contains("max_bytes") && params["max_bytes"].is_string()) {
            if (!is_whole_u64(params["max_bytes"].get<std::string>(), n) || n == 0)
                return ResilienceParamError{
                    "max_bytes must be a positive integer",
                    "set assertion.params.max_bytes >= 1 (bytes), or omit it for the default cap"};
            if (n > yuzu::guardian::kMaxFileHashBytes)
                return ResilienceParamError{
                    "max_bytes exceeds the 1 GiB agent-side ceiling",
                    "set assertion.params.max_bytes to at most 1073741824 (1 GiB)"};
        } else if (params.contains("max_bytes") && !params["max_bytes"].is_string()) {
            if (!params["max_bytes"].is_number_unsigned())
                return ResilienceParamError{
                    "max_bytes must be a positive integer",
                    "set assertion.params.max_bytes >= 1 (bytes), or omit it for the default cap"};
            if (params["max_bytes"].get<std::uint64_t>() > yuzu::guardian::kMaxFileHashBytes)
                return ResilienceParamError{
                    "max_bytes exceeds the 1 GiB agent-side ceiling",
                    "set assertion.params.max_bytes to at most 1073741824 (1 GiB)"};
        }
        if (params.contains("settle_ms") && params["settle_ms"].is_string() &&
            !is_whole_u64(params["settle_ms"].get<std::string>(), n))
            return ResilienceParamError{
                "settle_ms must be a non-negative integer",
                "set assertion.params.settle_ms in milliseconds, or omit it"};
        return std::nullopt;
    }

    // Service run-state assertions (service-running / service-stopped). The desired
    // state is the type suffix; bind it to the published kServiceStates set (H2) so a
    // state the agent does not arm — notably service-disabled — is rejected at
    // authoring rather than arming a confidently-wrong guard. The only param is the
    // SCM service name, validated against the agent's valid_service_name() charset so
    // a name the agent would reject cannot be authored.
    if (assertion_type.rfind("service-", 0) == 0) {
        const std::string state = assertion_type.substr(std::string_view("service-").size());
        if (!in_set(supported_service_states(), state))
            return ResilienceParamError{
                "unsupported service assertion '" + assertion_type + "'",
                "use an assertion published by GET /api/v1/guaranteed-state/schemas "
                "(service-running, service-stopped)"};
        const std::string svc = str_param(params, "service_name");
        if (svc.empty())
            return ResilienceParamError{
                "service assertion requires a non-empty 'service_name'",
                "set assertion.params.service_name to the SCM service (key) name, e.g. Spooler"};
        if (svc.size() > 256 || !std::all_of(svc.begin(), svc.end(), [](unsigned char c) {
                return std::isalnum(c) || c == '.' || c == '_' || c == '-' || c == '@';
            }))
            return ResilienceParamError{
                "invalid service_name '" + svc + "'",
                "service names are alphanumeric plus . _ - @ (max 256 chars)"};
        // Enforce-STOPPING a security service (Defender etc.) or the agent's own
        // service would turn Guardian into a security-control disabler / self-destruct
        // — gate it the same way enforce-writes to denylisted registry keys are gated
        // (H1). enforce service-running is protective and stays ungated.
        if (enforcement_mode == "enforce" && assertion_type == "service-stopped")
            if (std::string why = dangerous_enforce_service_stop(svc); !why.empty())
                return ResilienceParamError{
                    "enforce-mode stop of " + why + " is not permitted",
                    "author this Guard in audit mode (enforcement_mode=\"audit\") to observe its "
                    "state, or target a service outside the protected set"};
        return std::nullopt;
    }

    // Unknown assertion type is not this validator's job to gate — the agent marks
    // an unknown assertion errored (G11). derive_rule_spec validates only the
    // types we publish in the schema catalog.
    return std::nullopt;
}

} // namespace

std::string dangerous_enforce_registry_key(std::string_view key) {
    // Canonicalise to the path the registry actually resolves before matching the
    // denylist tokens: lowercase (registry is case-insensitive); '/'→'\' (forward
    // slash is not a registry separator); collapse repeated '\' runs (so a doubled
    // backslash can't dodge a token — MEDIUM-2). A leading '\' is then prepended so
    // the separator-anchored tokens ("\services\", "\policies\") match even when the
    // key begins with the component. The agent hands the raw key to
    // RegOpenKeyExW/RegCreateKeyExW, which ignore empty path components, so these
    // variants all resolve to the same key — the gate must treat them the same.
    std::string lowered = ascii_lower(key);
    std::string canon;
    canon.reserve(lowered.size() + 1);
    canon += '\\';
    bool prev_sep = true;
    for (char c : lowered) {
        if (c == '\\' || c == '/') {
            if (!prev_sep)
                canon += '\\';
            prev_sep = true;
        } else {
            canon += c;
            prev_sep = false;
        }
    }

    struct Denied {
        std::string_view token;
        std::string_view why;
    };
    static constexpr Denied kDenied[] = {
        {"currentversion\\run", "an autorun key (Run / RunOnce / RunServices)"},
        {"image file execution options", "an Image File Execution Options key (debugger hijack)"},
        {"winlogon", "a Winlogon key (Userinit / Shell logon hijack)"},
        {"\\services\\", "a service-configuration key (ImagePath / Start / Type)"},
        {"\\policies\\", "a system / explorer policy key"},
        {"safeboot", "the SafeBoot configuration"},
        {"bootexecute", "the Session Manager BootExecute autorun"},
    };
    for (const auto& d : kDenied)
        if (canon.find(d.token) != std::string::npos)
            return std::string(d.why);
    return {};
}

std::string dangerous_enforce_service_stop(std::string_view service_name) {
    // Enforce-STOPPING these would turn Guardian (a security-enforcement tool) into a
    // security-control disabler, or have the agent stop its own service (self-destruct
    // / flap). Detection (audit) on them is fine; enforce-stop is not. EXACT
    // case-insensitive match on the SCM key name — service names are case-insensitive
    // but not path-structured, so substring matching would over-block (e.g. a service
    // legitimately named "...EventLog..."). The service-control mirror of
    // dangerous_enforce_registry_key.
    const std::string lc = ascii_lower(service_name);
    struct Denied {
        std::string_view name;
        std::string_view why;
    };
    static constexpr Denied kDenied[] = {
        // Security controls — enforce-stopping these disables endpoint protection.
        {"windefend", "the Microsoft Defender Antivirus service"},
        {"wdnissvc", "the Microsoft Defender Network Inspection service"},
        {"sense", "the Microsoft Defender for Endpoint sensor"},
        {"wdfilter", "Microsoft Defender's filesystem minifilter — stopping it blinds "
                     "real-time scanning while WinDefend still reads as up (#1285)"},
        {"wscsvc", "the Windows Security Center service"},
        {"mpssvc", "the Windows Defender Firewall service"},
        {"bfe", "the Base Filtering Engine — the Windows Filtering Platform engine the "
                "firewall sits on; stopping it tears down the firewall while mpssvc still "
                "looks protected (#1285)"},
        {"eventlog", "the Windows Event Log service"},
        // Critical infrastructure — enforce-stopping these strands the agent itself
        // and breaks the host's ability to launch/recover services (self-inflicted
        // outage, not a security-control bypass, but equally catastrophic).
        {"rpcss", "the RPC subsystem (stopping it strands the agent and most Windows services)"},
        {"dcomlaunch", "the DCOM Server Process Launcher (stopping it breaks service launch/recovery)"},
        // The agent's own service — enforce-stop would be self-destruct / flap.
        {"yuzuagent", "the Yuzu agent's own service"},
    };
    for (const auto& d : kDenied)
        if (lc == d.name)
            return std::string(d.why);
    return {};
}

std::string dangerous_enforce_in_spec(const std::string& spec_json) {
    if (spec_json.empty())
        return {};
    auto spec = nlohmann::json::parse(spec_json, nullptr, /*allow_exceptions=*/false);
    if (!spec.is_object() || !spec.contains("assertion") || !spec["assertion"].is_object())
        return {};
    const auto& assertion = spec["assertion"];
    // str_param, not json::value(): value() throws type_error.302 on a PRESENT
    // non-string "type", and this gate must be total over arbitrary bytes — it
    // runs unguarded at the push chokepoint (#1946).
    const std::string atype = str_param(assertion, "type");
    if (!assertion.contains("params") || !assertion["params"].is_object())
        return {};
    const auto& params = assertion["params"];
    if (atype == "registry-value-equals") {
        if (!params.contains("key") || !params["key"].is_string())
            return {};
        return dangerous_enforce_registry_key(params["key"].get<std::string>());
    }
    if (atype == "service-stopped") {
        if (!params.contains("service_name") || !params["service_name"].is_string())
            return {};
        return dangerous_enforce_service_stop(params["service_name"].get<std::string>());
    }
    return {};
}

RuleSpecResult derive_rule_spec(const nlohmann::json& body, const std::string& name,
                                std::int64_t version, bool enabled,
                                const std::string& enforcement_mode) {
    RuleSpecResult out;

    auto json_block = [&](const char* key) -> nlohmann::json {
        if (body.contains(key) && body[key].is_object())
            return body[key];
        return nlohmann::json::object();
    };
    nlohmann::json spark = json_block("spark");
    nlohmann::json assertion = json_block("assertion");
    nlohmann::json remediation = json_block("remediation");
    const std::string spark_type = spark.value("type", std::string{});
    const std::string assertion_type = assertion.value("type", std::string{});

    const bool any_block = !spark.empty() || !assertion.empty() || !remediation.empty();
    const bool full = !spark_type.empty() && !assertion_type.empty();

    if (!full) {
        // A body carrying a structured block but not a complete spark+assertion
        // pair is rejected, NOT silently dropped (the silent-drop trap on update).
        // A body with no structured block at all is a legacy / metadata-only path
        // the caller owns.
        if (any_block)
            out.error = ResilienceParamError{
                "a structured Guard requires both a 'spark' and an 'assertion' block "
                "(each with a 'type')",
                "include spark.type and assertion.type, or omit all structured blocks for a "
                "metadata-only update"};
        return out;
    }

    // Validate the assertion params against the published supported sets (H2), the
    // enforce-write dangerous-key denylist (H1, contract §6) and file-assertion
    // sanity (M1) before building the spec. Rejected → HTTP 400 (A4 envelope).
    if (auto err = validate_assertion_params(assertion_type, assertion, enforcement_mode)) {
        out.error = std::move(err);
        return out;
    }

    // Detect-and-alert is the MVP default remediation.
    if (remediation.empty())
        remediation = {{"type", "alert-only"}, {"params", nlohmann::json::object()}};

    // C3b: validate + canonicalise the resilience policy in remediation.params.
    if (remediation.contains("params") && remediation["params"].is_object()) {
        if (auto err = validate_and_canonicalize_resilience_params(remediation["params"])) {
            out.error = std::move(err);
            return out;
        }
    }

    nlohmann::json spec;
    spec["name"] = name;
    spec["version"] = version;
    spec["enabled"] = enabled;
    spec["enforcement_mode"] = enforcement_mode;
    spec["spark"] = spark;
    spec["assertion"] = assertion;
    spec["remediation"] = remediation;

    out.structured = true;
    // Authoritative structured form. NOTE: a structured dump, not yet
    // JCS-canonicalised — full RFC-8785 canonicalisation lands with rule signing
    // (contract G3, deferred).
    out.spec_json = spec.dump();
    // yaml_source is a generated, never-parsed human-readable rendering (decision
    // 1). JSON is a valid YAML subset, so a header-commented pretty dump is honest.
    out.yaml_source =
        "# Guardian Guard (generated rendering — authoritative form is the structured spec)\n" +
        spec.dump(2) + "\n";
    return out;
}

} // namespace yuzu::server::guardian
