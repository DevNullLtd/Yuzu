#pragma once

/// @file json_extract.hpp
/// Shared JSON body-extraction helpers, consolidated out of two previously
/// independent copies (#2557): `server.cpp`'s seven `ServerImpl` statics and
/// `settings_routes.cpp`'s anonymous-namespace `extract_json_string`.
/// (Governance round 1, ARCH-2: the commit message this header shipped with
/// claimed three; only these two files were actually observed removing a
/// local copy at extraction time.) This is
/// a pure move — every function below is byte-identical in BEHAVIOR to the
/// copy it replaces (verified line-by-line against both originals before this
/// header was written), never a rewrite.
///
/// Header-only `inline` free functions in `namespace yuzu::server`, matching
/// the convention of `dispatch_target_shape.hpp` / `dispatch_confined_arms.hpp`
/// in this directory. Every existing unqualified call site inside a class
/// that itself lives in `namespace yuzu::server` (`ServerImpl`, `SettingsRoutes`)
/// resolves to these via ordinary unqualified lookup — no call site needed to
/// change.
///
/// THE STRING-TAKING OVERLOADS RE-PARSE `body` INDEPENDENTLY ON EVERY CALL and
/// swallow every parse/type exception, collapsing "omitted", "empty", "wrong
/// type" AND "parse failure" into the same neutral default. That erasure is
/// documented, load-bearing context for callers deciding dispatch-targeting
/// shape (#2500) — such a caller MUST NOT use these string-taking overloads
/// for a targeting field, and must instead call `check_targeting_shape` on an
/// already-parsed `nlohmann::json` object, then read fields from THAT object
/// directly via the json-taking overloads below. A second independent parse
/// of the same body can erase to empty under `std::bad_alloc` while an
/// earlier parse's validation already confirmed a non-empty value was
/// present — that mismatch is exactly what let a named-device dispatch
/// become a broadcast (#2500).

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>

namespace yuzu::server {

[[nodiscard]] inline std::string extract_json_string(const std::string& body,
                                                      const std::string& key) {
    try {
        auto j = nlohmann::json::parse(body);
        if (j.contains(key) && j[key].is_string()) {
            return j[key].get<std::string>();
        }
    } catch (...) {}
    return {};
}

[[nodiscard]] inline std::vector<std::string>
extract_json_string_array(const std::string& body, const std::string& key) {
    try {
        auto j = nlohmann::json::parse(body);
        if (j.contains(key) && j[key].is_array()) {
            std::vector<std::string> result;
            for (const auto& elem : j[key]) {
                if (elem.is_string()) {
                    result.push_back(elem.get<std::string>());
                }
            }
            return result;
        }
    } catch (...) {}
    return {};
}

[[nodiscard]] inline std::unordered_map<std::string, std::string>
extract_json_string_map(const std::string& body, const std::string& key) {
    try {
        auto j = nlohmann::json::parse(body);
        if (j.contains(key) && j[key].is_object()) {
            std::unordered_map<std::string, std::string> result;
            for (auto& [k, v] : j[key].items()) {
                if (v.is_string())
                    result[k] = v.get<std::string>();
                else
                    result[k] = v.dump();
            }
            return result;
        }
    } catch (...) {}
    return {};
}

[[nodiscard]] inline int32_t
extract_json_int(const std::string& body, const std::string& key, int32_t default_value = 0) {
    try {
        auto j = nlohmann::json::parse(body);
        if (j.contains(key) && j[key].is_number_integer()) {
            return j[key].get<int32_t>();
        }
    } catch (...) {}
    return default_value;
}

// ── json-taking overloads (#2500) ─────────────────────────────────────────
// The string-taking helpers above each parse the whole body independently.
// These let a handler that has ALREADY parsed reuse the object. Semantics
// are deliberately identical to their string twins — same key checks, same
// type checks, same fallbacks — so reusing the parse cannot change what a
// field resolves to.

[[nodiscard]] inline std::string extract_json_string(const nlohmann::json& j,
                                                      const std::string& key) {
    if (j.is_object() && j.contains(key) && j[key].is_string())
        return j[key].get<std::string>();
    return {};
}

[[nodiscard]] inline std::unordered_map<std::string, std::string>
extract_json_string_map(const nlohmann::json& j, const std::string& key) {
    std::unordered_map<std::string, std::string> result;
    if (j.is_object() && j.contains(key) && j[key].is_object()) {
        for (auto& [k, v] : j[key].items())
            result[k] = v.is_string() ? v.get<std::string>() : v.dump();
    }
    return result;
}

[[nodiscard]] inline int32_t
extract_json_int(const nlohmann::json& j, const std::string& key, int32_t default_value = 0) {
    if (j.is_object() && j.contains(key) && j[key].is_number_integer())
        return j[key].get<int32_t>();
    return default_value;
}

} // namespace yuzu::server
