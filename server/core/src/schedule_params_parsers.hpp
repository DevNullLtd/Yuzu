#pragma once

/// @file schedule_params_parsers.hpp
/// Pure validation + canonicalisation for `InstructionSchedule::parameter_values`
/// (PR1.5a). Header-only and I/O-free (no sqlite, no clock, no randomness) so
/// the decision-shaped logic is unit-tested independently of ScheduleEngine's
/// storage and ScheduleRunner's dispatch — the firewall_parsers.hpp /
/// interaction_parsers.hpp pattern applied to a JSON payload instead of shell
/// output.
///
/// Two entry points:
///   - `validate_and_canonicalize_schedule_params` is the untrusted-input
///     gate: `schedule_routes.cpp` calls it on the caller-supplied
///     `parameters` field, and `ScheduleEngine::create_schedule` calls it
///     again as a persistence-layer backstop (any direct caller — today only
///     tests — gets the same guarantee without going through the route).
///     Both calls are cheap: the second one canonicalizes an
///     already-canonical string, which is a no-op re-serialization.
///   - `schedule_params_to_map` is the read-side decode `ScheduleRunner::
///     dispatch_tracked` uses to turn a stored canonical blob back into the
///     `std::unordered_map<std::string,std::string>` the shared
///     `CommandDispatchFn` expects.
///
/// Canonical form: an `nlohmann::json` object's default `object_t` is
/// `std::map<std::string, json>`, so building the output object key-by-key
/// and calling the library's own `.dump()` (no indent) ALWAYS emits keys in
/// ascending byte order — two logically-identical parameter sets, written in
/// different key order by the caller, serialize byte-identically. p8 feeds
/// this canonical string into the plan hash, so that determinism is load
/// bearing, not cosmetic.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <unordered_map>

namespace yuzu::server {

/// The canonical form of "no parameters" — what a create-schedule request
/// that omits `parameters` entirely resolves to, and what the schema
/// migration back-fills into every pre-existing row (schedule_engine.cpp).
inline constexpr std::string_view kEmptyScheduleParams = "{}";

/// Hard caps (denial-of-service floor, not a product limit). An unbounded key
/// count inflates every dispatch fn call's parameter map on every fire; an
/// unbounded serialized size inflates the plan-hash input p8 derives from the
/// canonical string and the schedules row itself.
inline constexpr std::size_t kMaxScheduleParamKeys = 32;
inline constexpr std::size_t kMaxScheduleParamsBytes = 4096;

/// Why validation rejected the input. Typed rather than string-matched so a
/// caller (schedule_routes.cpp today, tests always) can map a specific
/// reason to a specific operator-facing message without parsing prose.
enum class ScheduleParamsError {
    kMalformedJson,  ///< not parseable JSON at all
    kNotObject,      ///< top-level value parses, but is not a `{}` object
    kNonScalarValue, ///< a value is an object, array, or null
    kTooManyKeys,    ///< key count exceeds kMaxScheduleParamKeys
    kTooLarge,       ///< canonical serialization exceeds kMaxScheduleParamsBytes
    kReservedKey,    ///< a key is empty or underscore-prefixed
};

[[nodiscard]] constexpr std::string_view to_string(ScheduleParamsError e) {
    switch (e) {
    case ScheduleParamsError::kMalformedJson:
        return "parameters must be valid JSON";
    case ScheduleParamsError::kNotObject:
        return "parameters must be a JSON object";
    case ScheduleParamsError::kNonScalarValue:
        return "parameter values must be a string, number, or boolean";
    case ScheduleParamsError::kTooManyKeys:
        return "too many parameters";
    case ScheduleParamsError::kTooLarge:
        return "parameters exceed the size limit";
    case ScheduleParamsError::kReservedKey:
        return "parameter keys must not be empty or start with '_'";
    }
    return "invalid parameters"; // unreachable — cases are exhaustive so -Wswitch flags enum drift
}

/// Keys starting with `_` (and the empty key) are reserved for
/// server-internal parameter injection at dispatch time — a caller-supplied
/// `_principal` or similar must never be able to shadow one of those.
[[nodiscard]] constexpr bool is_reserved_schedule_param_key(std::string_view key) {
    return key.empty() || key.front() == '_';
}

/// Validate an untrusted JSON blob and produce its canonical serialization.
/// An empty `raw_json` (an omitted `parameters` field) is treated exactly
/// like `"{}"`, not as malformed input.
[[nodiscard]] inline std::expected<std::string, ScheduleParamsError>
validate_and_canonicalize_schedule_params(std::string_view raw_json) {
    if (raw_json.empty())
        return std::string(kEmptyScheduleParams);

    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(raw_json);
    } catch (const nlohmann::json::exception&) {
        return std::unexpected(ScheduleParamsError::kMalformedJson);
    }

    if (!parsed.is_object())
        return std::unexpected(ScheduleParamsError::kNotObject);

    if (parsed.size() > kMaxScheduleParamKeys)
        return std::unexpected(ScheduleParamsError::kTooManyKeys);

    // Built key-by-key (rather than mutating `parsed` in place) so a caller
    // that sent extra top-level noise nlohmann tolerates cannot smuggle
    // anything through unexamined — every key that survives has been through
    // the reserved-prefix and scalar-type checks below.
    nlohmann::json canonical = nlohmann::json::object();
    for (const auto& [key, value] : parsed.items()) {
        if (is_reserved_schedule_param_key(key))
            return std::unexpected(ScheduleParamsError::kReservedKey);
        // Deliberately NOT `value.is_primitive()`: that predicate also
        // accepts `null`, which this validator rejects — a schedule
        // parameter has no meaningful "present but null" state, and letting
        // one through would hand dispatch_fn a parameter whose stringified
        // form ("null") looks like a value a plugin could act on.
        if (!(value.is_string() || value.is_boolean() || value.is_number()))
            return std::unexpected(ScheduleParamsError::kNonScalarValue);
        canonical[key] = value;
    }

    auto serialized = canonical.dump();
    if (serialized.size() > kMaxScheduleParamsBytes)
        return std::unexpected(ScheduleParamsError::kTooLarge);

    return serialized;
}

/// Decode a canonical parameter blob (as produced above) into the flat
/// string map `ScheduleRunner::dispatch_tracked` threads into the shared
/// `CommandDispatchFn`. String values are unwrapped (no surrounding JSON
/// quotes); every other scalar renders via its own JSON literal (`true`,
/// `42`, `3.5`) since the destination is a string-valued map.
///
/// Assumes `canonical_json` already passed `validate_and_canonicalize_
/// schedule_params` — every write path in this package guarantees that. A
/// blob that somehow reached this function un-validated (hand-edited
/// storage) degrades gracefully to an empty map rather than throwing: a
/// scheduled fire must never crash on a malformed parameter blob.
[[nodiscard]] inline std::unordered_map<std::string, std::string>
schedule_params_to_map(std::string_view canonical_json) {
    std::unordered_map<std::string, std::string> out;
    if (canonical_json.empty())
        return out;

    nlohmann::json parsed;
    try {
        parsed = nlohmann::json::parse(canonical_json);
    } catch (const nlohmann::json::exception&) {
        return out;
    }
    if (!parsed.is_object())
        return out;

    for (const auto& [key, value] : parsed.items())
        out[key] = value.is_string() ? value.get<std::string>() : value.dump();

    return out;
}

} // namespace yuzu::server
