#pragma once

/**
 * @file dex_score_policy_json.hpp
 * Pure JSON mapping for the customer score policy: the persisted document, its
 * canonical text, its revision token, and the policy in force for a stored text.
 *
 * Header-only; nlohmann::json and the standard library plus the pure DEX model
 * headers and the shared log_token helper. No I/O, no clock, no store.
 *
 * ONE DOCUMENT, ONE KEY, ONE WRITER. The whole policy is a single JSON document
 * stored under the runtime-config key kDexScorePolicyKey. It is written only by
 * the policy writer (apply_dex_score_policy, dex_score_policy_writer.hpp:
 * validate, persist the canonical text); the generic runtime-config write
 * refuses the key, so no other path can leave the document half-edited. Every
 * server instance reads the same row.
 *
 * NOT part of the document: the cohort floor and the statistics. They are fixed
 * constants of the score, not settings. (The interval confidence LEVEL is a
 * setting: it is the `model` block's, below.)
 *
 * VERSIONS. Version 1 is the document before the model parameters existed;
 * version 2 adds the `model` block. The writer stamps version 2 ONLY when the
 * policy uses a model parameter (dex_score_policy_uses_model_parameters: a
 * global value off its default, or ANY override naming a model field, even at
 * the global value, because presence pins the application). Every other policy
 * dumps as exactly the version-1 text it always did, so an existing stored
 * document's revision never changes and an older replica keeps reading it. The
 * reader enforces the other direction: `model` (root or override) in a
 * document below version 2 is refused as "requires version 2", so "model
 * present implies version 2" holds for every stored text, and a replica that
 * only knows version 1 falls back whole on a version-2 text.
 *
 * Failure direction (the reader's contract, see dex_policy_in_force_from_stored):
 *   - nothing stored        -> the shipped defaults, source "default", no fault.
 *   - stored text invalid   -> the shipped defaults, source "default", `fault`
 *                              names the reason. Never half-applied.
 *   - version above the one this build supports
 *                           -> the shipped defaults, source "default", `fault`
 *                              "unsupported_version at version: N above the supported 2",
 *                              checked BEFORE the strict parse so a newer document with
 *                              keys this reader does not know still falls back whole.
 *   - store unreadable      -> not decided here; the provider serves the last
 *                              good policy for a bounded time, then refuses.
 *
 * Wire shape (every key optional on read except an override's "image"; unknown
 * keys are refused):
 *   { "version": 1 | 2,
 *     "tiers":   { "edges": {excellent, good, fair},
 *                  "names": {excellent, good, fair, poor} },
 *     "weights": { breadth, crashes, hangs, regression },
 *     "model":   { per_device_event_cap, regression_full_ratio,
 *                  regression_start_ratio, interval_confidence },   // version 2
 *     "overrides": [ { "image": "<exact image name>",
 *                      "tiers":   { "edges": {..}, "names": {..} },
 *                      "weights": {..},
 *                      "model":   { per_device_event_cap, regression_full_ratio,
 *                                   regression_start_ratio } } ] }   // version 2
 * An override's model has no interval_confidence (global only; an unknown key
 * there). per_device_event_cap must be a JSON integer.
 * "version" is an integer of at least 1; absent reads as 1, and the canonical text
 * always carries it. An override sets only the fields it names; the rest inherit the global policy.
 * Numbers must be JSON numbers (the string "90" is refused). Poor's lower edge
 * is fixed at 0 and is not part of the document. The `tiers` block of an Apps
 * response is a read-model projection (tiers.<tier>.{edge,name}), not this stored
 * shape.
 *
 * Bounded text: a stored text over kDexScorePolicyMaxBytes is refused without being
 * parsed, and the only caller-controlled text a fault can carry is an unknown key,
 * which is neutralised and capped at yuzu::kGuardianLogIdMaxBytes; every other fault
 * string is a literal of ours plus an index that the size cap bounds.
 */

#include "dex_read_model.hpp"
#include "dex_score_policy.hpp"

#include <nlohmann/json.hpp>
#include <yuzu/log_token.hpp> // log_key_token: neutralise and cap document text

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <format>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::server {

/// Runtime-config key holding the policy document.
inline constexpr std::string_view kDexScorePolicyKey = "dex_score_policy";
/// The highest document version this build reads, and the one it writes when a
/// model parameter is in use.
inline constexpr std::int64_t kDexScorePolicyVersion = 2;
/// The version of a document with no model parameter, and of every document
/// written before the model parameters existed.
inline constexpr std::int64_t kDexScorePolicyBaseVersion = 1;
/// Revision reported when no document is stored.
inline constexpr std::string_view kDexScorePolicyDefaultRevision = "default";
/// Largest stored text that is parsed. A legitimate document is about 130 KB at the
/// override limit (at most about 185 KB when image keys and names need escaping); anything
/// larger is refused unread.
inline constexpr std::size_t kDexScorePolicyMaxBytes = 256 * 1024;

/// A document that is not the expected shape. `field` is the dotted path of the
/// offending value (for example "overrides[2].weights.crashes"), "document" for
/// the root.
struct DexPolicyParseError {
    std::string field;
    std::string message;
};

namespace dex_score_policy_json_detail {

using json = nlohmann::json;
using Err = DexPolicyParseError;

[[nodiscard]] inline std::string join(std::string_view path, std::string_view key) {
    return path.empty() ? std::string(key) : std::string(path) + "." + std::string(key);
}

/// A key not in `known` is refused with its own path. The key is document text, so it
/// is neutralised (control bytes folded) and capped before it reaches a fault, which
/// is logged and returned on every Apps response.
[[nodiscard]] inline std::optional<Err>
unknown_key(const json& o, std::string_view path,
            std::initializer_list<std::string_view> known) {
    for (auto it = o.begin(); it != o.end(); ++it)
        if (std::find(known.begin(), known.end(), std::string_view(it.key())) == known.end())
            return Err{join(path, yuzu::log_key_token(it.key())), "unknown key"};
    return std::nullopt;
}

/// `o[key]` as an object, nullptr when absent; a non-object value is refused.
[[nodiscard]] inline std::expected<const json*, Err>
object_at(const json& o, std::string_view path, std::string_view key) {
    const auto it = o.find(std::string(key));
    if (it == o.end())
        return nullptr;
    if (!it->is_object())
        return std::unexpected(Err{join(path, key), "must be an object"});
    return &*it;
}

/// Reads the listed numeric fields of object `o` into their targets (`double`
/// or `std::optional<double>`); an absent key leaves its target untouched.
template <class T>
[[nodiscard]] std::optional<Err>
read_numbers(const json& o, std::string_view path,
             std::initializer_list<std::pair<std::string_view, T*>> fields) {
    for (const auto& [key, dst] : fields)
        if (const auto it = o.find(std::string(key)); it != o.end()) {
            if (!it->is_number())
                return Err{join(path, key), "must be a number"};
            *dst = it->template get<double>();
        }
    return std::nullopt;
}

template <class T>
[[nodiscard]] std::optional<Err>
read_strings(const json& o, std::string_view path,
             std::initializer_list<std::pair<std::string_view, T*>> fields) {
    for (const auto& [key, dst] : fields)
        if (const auto it = o.find(std::string(key)); it != o.end()) {
            if (!it->is_string())
                return Err{join(path, key), "must be a string"};
            *dst = it->template get<std::string>();
        }
    return std::nullopt;
}

/// The "tiers" object, shared by the global policy (double / std::string
/// targets) and an override (optional targets).
template <class E, class N>
[[nodiscard]] std::optional<Err> read_tiers(const json& tiers, std::string_view path,
                                            std::array<E*, 3> edges, std::array<N*, 4> names) {
    if (const auto e = unknown_key(tiers, path, {"edges", "names"}))
        return e;
    const auto eo = object_at(tiers, path, "edges");
    if (!eo)
        return eo.error();
    if (*eo) {
        const std::string p = join(path, "edges");
        if (const auto e = unknown_key(**eo, p, {"excellent", "good", "fair"}))
            return e;
        if (const auto e = read_numbers<E>(**eo, p,
                                           {{"excellent", edges[0]}, {"good", edges[1]},
                                            {"fair", edges[2]}}))
            return e;
    }
    const auto no = object_at(tiers, path, "names");
    if (!no)
        return no.error();
    if (*no) {
        const std::string p = join(path, "names");
        if (const auto e = unknown_key(**no, p, {"excellent", "good", "fair", "poor"}))
            return e;
        if (const auto e = read_strings<N>(**no, p,
                                           {{"excellent", names[0]}, {"good", names[1]},
                                            {"fair", names[2]}, {"poor", names[3]}}))
            return e;
    }
    return std::nullopt;
}

template <class T>
[[nodiscard]] std::optional<Err> read_weights(const json& o, std::string_view path,
                                              std::array<T*, 4> w) {
    const auto wo = object_at(o, path, "weights");
    if (!wo)
        return wo.error();
    if (!*wo)
        return std::nullopt;
    const std::string p = join(path, "weights");
    if (const auto e = unknown_key(**wo, p, {"breadth", "crashes", "hangs", "regression"}))
        return e;
    return read_numbers<T>(**wo, p,
                           {{"breadth", w[0]}, {"crashes", w[1]}, {"hangs", w[2]},
                            {"regression", w[3]}});
}

/// The "model" object, shared by the global policy (plain targets) and an
/// override (optional targets, `confidence` null: interval_confidence is global
/// only, so inside an override it is an unknown key). The cap must be a JSON
/// integer (an unsigned above INT64_MAX clamps and the validator refuses it).
template <class I, class D>
[[nodiscard]] std::optional<Err> read_model(const json& o, std::string_view path, I* cap, D* full,
                                            D* start, double* confidence) {
    const auto mo = object_at(o, path, "model");
    if (!mo)
        return mo.error();
    if (!*mo)
        return std::nullopt;
    const std::string p = join(path, "model");
    if (confidence) {
        if (const auto e = unknown_key(**mo, p,
                                       {"per_device_event_cap", "regression_full_ratio",
                                        "regression_start_ratio", "interval_confidence"}))
            return e;
    } else if (const auto e = unknown_key(**mo, p,
                                          {"per_device_event_cap", "regression_full_ratio",
                                           "regression_start_ratio"})) {
        return e;
    }
    if (const auto it = (*mo)->find("per_device_event_cap"); it != (*mo)->end()) {
        if (!it->is_number_integer())
            return Err{join(p, "per_device_event_cap"), "must be an integer"};
        constexpr auto kMax = (std::numeric_limits<std::int64_t>::max)();
        *cap = it->is_number_unsigned() && it->template get<std::uint64_t>() >
                                               static_cast<std::uint64_t>(kMax)
                   ? kMax
                   : it->template get<std::int64_t>();
    }
    if (const auto e = read_numbers<D>(**mo, p,
                                       {{"regression_full_ratio", full},
                                        {"regression_start_ratio", start}}))
        return e;
    if (confidence)
        return read_numbers<double>(**mo, p, {{"interval_confidence", confidence}});
    return std::nullopt;
}

/// File-local FNV-1a 64-bit, 16 lower-hex digits.
[[nodiscard]] inline std::string fnv1a64_hex(std::string_view s) {
    std::uint64_t h = 14695981039346656037ull; // FNV-1a 64 offset basis
    for (const unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return std::format("{:016x}", h);
}

} // namespace dex_score_policy_json_detail

/// The document's version: absent (or a non-object root, which the parser reports) reads
/// as 1; anything that is not an integer of at least 1 is a parse error at `version`.
[[nodiscard]] inline std::expected<std::int64_t, DexPolicyParseError>
dex_score_policy_document_version(const nlohmann::json& doc) {
    if (!doc.is_object())
        return 1;
    const auto it = doc.find("version");
    if (it == doc.end())
        return 1;
    if (!it->is_number_integer())
        return std::unexpected(
            DexPolicyParseError{"version", "must be an integer of at least 1"});
    // An unsigned value above INT64_MAX would wrap negative in get<std::int64_t>() and read
    // as "< 1" instead of "above the supported version": clamp it, it is still above.
    constexpr auto kMax = (std::numeric_limits<std::int64_t>::max)();
    const std::int64_t v =
        it->is_number_unsigned() && it->get<std::uint64_t>() > static_cast<std::uint64_t>(kMax)
            ? kMax
            : it->get<std::int64_t>();
    if (v < 1)
        return std::unexpected(
            DexPolicyParseError{"version", "must be an integer of at least 1"});
    return v;
}

/// Strict parse. Refuses an unknown key, a wrong type and a non-object where an
/// object is required, naming the offending path; nothing is partially returned.
/// Each override image is ASCII-folded here (the writer's job per the
/// validator's banner), so a document with "Outlook.EXE" validates as
/// "outlook.exe". Range and consistency checks are NOT done here: the result
/// goes through dex_score_policy_fault.
[[nodiscard]] inline std::expected<DexScorePolicy, DexPolicyParseError>
dex_score_policy_from_json(const nlohmann::json& doc) {
    using namespace dex_score_policy_json_detail;
    if (!doc.is_object())
        return std::unexpected(Err{"document", "must be an object"});
    // The writer side: a bad version, or one above what this build writes, is refused
    // FIRST, so a newer document with keys this build does not know is reported as
    // what it is rather than as its first unknown key.
    const auto ver = dex_score_policy_document_version(doc);
    if (!ver)
        return std::unexpected(ver.error());
    if (*ver > kDexScorePolicyVersion)
        return std::unexpected(Err{"version", "above the supported " +
                                                  std::to_string(kDexScorePolicyVersion)});
    if (const auto e = unknown_key(doc, "", {"version", "tiers", "weights", "model", "overrides"}))
        return std::unexpected(*e);
    // `model` is a version-2 key: below it the document is refused, so the writer's
    // stamp and the reader's check agree and an older replica never half-reads one.
    const bool model_allowed = *ver >= 2;
    DexScorePolicy p;
    const auto to = object_at(doc, "", "tiers");
    if (!to)
        return std::unexpected(to.error());
    if (*to)
        if (const auto e = read_tiers<double, std::string>(
                **to, "tiers",
                {&p.tiers.edges.excellent, &p.tiers.edges.good, &p.tiers.edges.fair},
                {&p.tiers.names[0], &p.tiers.names[1], &p.tiers.names[2], &p.tiers.names[3]}))
            return std::unexpected(*e);
    if (const auto e = read_weights<double>(
            doc, "", {&p.weights.breadth, &p.weights.crashes, &p.weights.hangs,
                      &p.weights.regression}))
        return std::unexpected(*e);
    if (doc.contains("model")) {
        if (!model_allowed)
            return std::unexpected(Err{"model", "requires version 2"});
        if (const auto e = read_model<std::int64_t, double>(
                doc, "", &p.model.per_device_event_cap, &p.model.regression_full_ratio,
                &p.model.regression_start_ratio, &p.interval_confidence))
            return std::unexpected(*e);
    }
    if (const auto it = doc.find("overrides"); it != doc.end()) {
        if (!it->is_array())
            return std::unexpected(Err{"overrides", "must be an array"});
        for (std::size_t i = 0; i < it->size(); ++i) {
            const json& o = (*it)[i];
            const std::string path = "overrides[" + std::to_string(i) + "]";
            if (!o.is_object())
                return std::unexpected(Err{path, "must be an object"});
            if (const auto e = unknown_key(o, path, {"image", "tiers", "weights", "model"}))
                return std::unexpected(*e);
            DexScoreOverride ov;
            const auto img = o.find("image");
            if (img == o.end() || !img->is_string())
                return std::unexpected(Err{join(path, "image"), "must be a string"});
            ov.image = dex_score_policy_detail::ascii_lower(img->get<std::string>());
            const auto ot = object_at(o, path, "tiers");
            if (!ot)
                return std::unexpected(ot.error());
            if (*ot)
                if (const auto e = read_tiers<std::optional<double>, std::optional<std::string>>(
                        **ot, join(path, "tiers"), {&ov.excellent, &ov.good, &ov.fair},
                        {&ov.names[0], &ov.names[1], &ov.names[2], &ov.names[3]}))
                    return std::unexpected(*e);
            if (const auto e = read_weights<std::optional<double>>(
                    o, path, {&ov.breadth, &ov.crashes, &ov.hangs, &ov.regression}))
                return std::unexpected(*e);
            if (o.contains("model")) {
                if (!model_allowed)
                    return std::unexpected(Err{join(path, "model"), "requires version 2"});
                if (const auto e = read_model<std::optional<std::int64_t>, std::optional<double>>(
                        o, path, &ov.per_device_event_cap, &ov.regression_full_ratio,
                        &ov.regression_start_ratio, nullptr))
                    return std::unexpected(*e);
            }
            p.overrides.push_back(std::move(ov));
        }
    }
    return p;
}

/// True when the policy needs the version-2 document: a global model value off
/// its default, or any override naming a model field (presence, not value, so an
/// override pinned at the shipped value still pins that application when the
/// global one later changes). False means the canonical text is the version-1
/// text, with no `model` key anywhere.
[[nodiscard]] inline bool dex_score_policy_uses_model_parameters(const DexScorePolicy& p) {
    if (!(p.model == kStabilityModel) || p.interval_confidence != kDexStatsConfidence)
        return true;
    return std::any_of(p.overrides.begin(), p.overrides.end(), [](const DexScoreOverride& o) {
        return o.per_device_event_cap || o.regression_full_ratio || o.regression_start_ratio;
    });
}

/// The full global document plus, per override, only the fields it sets. Key
/// order is fixed (nlohmann objects are key-sorted), so equal policies dump to
/// equal text. A policy that uses no model parameter dumps EXACTLY the version-1
/// text it always did (equal text, equal revision); otherwise version 2 with the
/// root `model` (all four fields) and each override's `model` (only the fields
/// it sets).
[[nodiscard]] inline nlohmann::json dex_score_policy_to_json(const DexScorePolicy& p) {
    using json = nlohmann::json;
    const bool v2 = dex_score_policy_uses_model_parameters(p);
    json edges{{"excellent", p.tiers.edges.excellent},
               {"good", p.tiers.edges.good},
               {"fair", p.tiers.edges.fair}};
    json names{{"excellent", p.tiers.names[0]},
               {"good", p.tiers.names[1]},
               {"fair", p.tiers.names[2]},
               {"poor", p.tiers.names[3]}};
    json doc{{"version", v2 ? kDexScorePolicyVersion : kDexScorePolicyBaseVersion},
             {"tiers", {{"edges", std::move(edges)}, {"names", std::move(names)}}},
             {"weights",
              {{"breadth", p.weights.breadth},
               {"crashes", p.weights.crashes},
               {"hangs", p.weights.hangs},
               {"regression", p.weights.regression}}}};
    if (v2)
        doc["model"] = {{"per_device_event_cap", p.model.per_device_event_cap},
                        {"regression_full_ratio", p.model.regression_full_ratio},
                        {"regression_start_ratio", p.model.regression_start_ratio},
                        {"interval_confidence", p.interval_confidence}};
    json arr = json::array();
    for (const auto& o : p.overrides) {
        json oe = json::object(), on = json::object(), ow = json::object();
        if (o.excellent)
            oe["excellent"] = *o.excellent;
        if (o.good)
            oe["good"] = *o.good;
        if (o.fair)
            oe["fair"] = *o.fair;
        static constexpr const char* kTier[4] = {"excellent", "good", "fair", "poor"};
        for (std::size_t i = 0; i < 4; ++i)
            if (o.names[i])
                on[kTier[i]] = *o.names[i];
        if (o.breadth)
            ow["breadth"] = *o.breadth;
        if (o.crashes)
            ow["crashes"] = *o.crashes;
        if (o.hangs)
            ow["hangs"] = *o.hangs;
        if (o.regression)
            ow["regression"] = *o.regression;
        json om = json::object();
        if (o.per_device_event_cap)
            om["per_device_event_cap"] = *o.per_device_event_cap;
        if (o.regression_full_ratio)
            om["regression_full_ratio"] = *o.regression_full_ratio;
        if (o.regression_start_ratio)
            om["regression_start_ratio"] = *o.regression_start_ratio;
        json ov{{"image", o.image}};
        json tiers = json::object();
        if (!oe.empty())
            tiers["edges"] = std::move(oe);
        if (!on.empty())
            tiers["names"] = std::move(on);
        if (!tiers.empty())
            ov["tiers"] = std::move(tiers);
        if (!ow.empty())
            ov["weights"] = std::move(ow);
        if (!om.empty())
            ov["model"] = std::move(om);
        arr.push_back(std::move(ov));
    }
    doc["overrides"] = std::move(arr);
    return doc;
}

/// The text a writer stores.
[[nodiscard]] inline std::string dex_score_policy_canonical(const DexScorePolicy& p) {
    return dex_score_policy_to_json(p).dump();
}

/// Revision token of a stored text: 16 lower-hex digits (FNV-1a 64) of the text
/// as stored, so equal text reads as equal revision on every instance. A
/// content hash, not a security digest. kDexScorePolicyDefaultRevision when
/// nothing is stored (nullopt or empty).
[[nodiscard]] inline std::string dex_score_policy_revision(std::string_view stored_text) {
    if (stored_text.empty())
        return std::string(kDexScorePolicyDefaultRevision);
    return dex_score_policy_json_detail::fnv1a64_hex(stored_text);
}

/// Field path of a validator rejection. The validator reports the group that
/// failed, not the single edge or weight, so the path names the group
/// (tiers.edges, tiers.names, weights, model); a per-override fault carries the
/// override's index.
[[nodiscard]] inline std::string dex_policy_fault_field(const DexPolicyRejection& r) {
    if (r.fault == DexPolicyFault::TooManyOverrides)
        return "overrides";
    const bool global = r.override_index == kDexPolicyGlobalIndex;
    const std::string base = global ? std::string()
                                    : "overrides[" + std::to_string(r.override_index) + "].";
    switch (r.fault) {
    case DexPolicyFault::EdgeOutOfRange:
    case DexPolicyFault::EdgeNotDisplayExact:
    case DexPolicyFault::EdgesNotDescending:
    case DexPolicyFault::EdgeGapBelowMinimum:
        return base + "tiers.edges";
    case DexPolicyFault::NameInvalid:
        return base + "tiers.names";
    case DexPolicyFault::WeightInvalid:
    case DexPolicyFault::WeightSumAboveMaximum:
        return base + "weights";
    case DexPolicyFault::EventCapOutOfRange:
    case DexPolicyFault::RegressionRatioOutOfRange:
    case DexPolicyFault::RegressionRatiosNotAscending:
    case DexPolicyFault::IntervalConfidenceOutOfRange:
        return base + "model";
    case DexPolicyFault::OverrideKeyInvalid:
    case DexPolicyFault::OverrideKeyDuplicate:
        return global ? std::string("overrides") : base + "image";
    case DexPolicyFault::TooManyOverrides:
        break;
    }
    return "overrides";
}

/// Validate a policy document text whole: the size cap, JSON parse, version (read before the
/// strict parse), strict parse and range validator, in that order. The one validation both
/// the reader (dex_policy_in_force_from_stored) and the writer use, so a text the writer
/// accepts is a text the reader serves, and the two never word a refusal differently.
/// On refusal `.field` is the dotted path of the offending value ("document" for the root) and
/// `.message` is the fault string the reader reports: "oversized at document: ...",
/// "unparseable at <path>: <msg>", "unsupported_version at version: N above the supported 2" or
/// "<validator token> at <path>".
[[nodiscard]] inline std::expected<DexScorePolicy, DexPolicyParseError>
dex_score_policy_validate_text(const std::string& text) {
    using Err = DexPolicyParseError;
    if (text.size() > kDexScorePolicyMaxBytes)
        return std::unexpected(Err{"document", "oversized at document: more than " +
                                                   std::to_string(kDexScorePolicyMaxBytes) +
                                                   " bytes"});
    const auto doc = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded())
        return std::unexpected(Err{"document", "unparseable at document: not valid JSON"});
    // A newer document may carry keys this reader does not know, so its version is read
    // BEFORE the strict parse: it falls back whole, never half-applied. A malformed
    // version falls through to the parser, which reports it at `version`.
    if (const auto v = dex_score_policy_document_version(doc); v && *v > kDexScorePolicyVersion)
        return std::unexpected(Err{"version", "unsupported_version at version: " +
                                                  std::to_string(*v) + " above the supported " +
                                                  std::to_string(kDexScorePolicyVersion)});
    auto parsed = dex_score_policy_from_json(doc);
    if (!parsed)
        return std::unexpected(Err{parsed.error().field, "unparseable at " + parsed.error().field +
                                                             ": " + parsed.error().message});
    if (const auto f = dex_score_policy_fault(*parsed)) {
        const std::string field = dex_policy_fault_field(*f);
        return std::unexpected(
            Err{field, std::string(dex_policy_fault_label(f->fault)) + " at " + field});
    }
    return parsed;
}

/// The policy to score under for a stored text. nullopt or empty is the shipped
/// defaults with no fault. Unparseable or invalid text is the shipped defaults
/// with `fault` naming why; the revision is that of the text as stored, so an
/// operator can tell which document is being refused. Never half-applied.
[[nodiscard]] inline DexPolicyInForce
dex_policy_in_force_from_stored(const std::optional<std::string>& stored) {
    DexPolicyInForce out;
    out.policy = dex_default_score_policy();
    if (!stored || stored->empty())
        return out;
    out.revision = dex_score_policy_revision(*stored);
    auto v = dex_score_policy_validate_text(*stored);
    if (!v) {
        out.fault = std::move(v.error().message);
        return out;
    }
    out.policy = std::move(*v);
    out.source = "custom";
    return out;
}

/// The hint a refusal carries when `field` names a key of the Apps read-model policy block
/// (tiers.<tier>.{edge,name}, source, revision, fault) rather than of the stored document:
/// that block is a projection, and sending it back is the likeliest way to get a refusal.
/// Empty for every other field.
[[nodiscard]] inline std::string_view
dex_score_policy_projection_remediation(std::string_view field) noexcept {
    for (const std::string_view f : {"tiers.excellent", "tiers.good", "tiers.fair", "tiers.poor",
                                     "source", "revision", "fault", "policy"})
        if (field == f)
            return "the Apps policy block is a projection; send the stored shape "
                   "(tiers.edges, tiers.names, weights, overrides)";
    return {};
}

} // namespace yuzu::server
