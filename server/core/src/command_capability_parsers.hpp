#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <string_view>

#include "command_capability.hpp"

/// @file command_capability_parsers.hpp
/// The pure, header-only helpers `CommandCapabilityRegistry` classification
/// consumers need around a lookup: normalizing a `plugin.action` pair the
/// same way `CommandCapabilityRegistry::classify` does internally, hashing a
/// dispatch plan into a stable identity, and encoding/decoding the frozen
/// `v1|<class>|<mutability>|<plan_hash_hex>` wire grammar p3 mirrors into the
/// proto comment and p8 puts on the wire. None of this allocates on
/// `CommandCapabilityRegistry::classify`'s lookup path — these are separate,
/// ordinary (non-`noexcept`, heap-using where convenient) helpers for the
/// callers around it.
namespace yuzu::server {

namespace command_capability_detail {

[[nodiscard]] constexpr char to_lower_ascii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// ── FNV-1a, two independently-seeded 64-bit lanes ────────────────────────
// `compute_plan_hash` needs a deterministic, portable, dependency-free
// digest — not cryptographic strength (this is a dedup/identity key, never a
// security boundary), so a hand-rolled SHA-256 or an OpenSSL dependency
// would be more machinery than the contract calls for. Two lanes (128 bits
// of output) keep accidental collisions between distinct dispatch plans
// vanishingly unlikely without pulling in a crypto library from a header
// three other packages' fragment headers transitively include.
inline constexpr uint64_t kFnvOffsetLaneA = 0xcbf29ce484222325ULL;
inline constexpr uint64_t kFnvPrimeLaneA = 0x100000001b3ULL;
inline constexpr uint64_t kFnvOffsetLaneB = 0x84222325cbf29ce4ULL;
inline constexpr uint64_t kFnvPrimeLaneB = 0x0000013b00000001ULL;

[[nodiscard]] inline uint64_t fnv1a(uint64_t seed, std::string_view data, uint64_t prime) noexcept {
    uint64_t h = seed;
    for (unsigned char c : data) {
        h ^= c;
        h *= prime;
    }
    return h;
}

[[nodiscard]] inline std::string to_hex_lower_u64(uint64_t v) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string out(16, '0');
    for (std::size_t i = 16; i-- > 0;) {
        out[i] = kHexDigits[v & 0xF];
        v >>= 4;
    }
    return out;
}

} // namespace command_capability_detail

/// The normalized `"<plugin>.<action>"` lookup key: both components
/// lowercased, joined by a literal `.`. Mirrors the case-insensitive
/// comparison `CommandCapabilityRegistry::classify` performs internally
/// (which never materializes this string, to stay heap-free on the lookup
/// path) — this is the allocating twin for callers that need the key itself,
/// e.g. as a map key or a log field.
[[nodiscard]] inline std::string normalize_action_key(std::string_view plugin,
                                                       std::string_view action) {
    std::string out;
    out.reserve(plugin.size() + action.size() + 1);
    for (char c : plugin)
        out.push_back(command_capability_detail::to_lower_ascii(c));
    out.push_back('.');
    for (char c : action)
        out.push_back(command_capability_detail::to_lower_ascii(c));
    return out;
}

/// A stable, deterministic identity for one dispatch plan: the same
/// `(plugin, action, parameters, target_arm, execution_id)` tuple always
/// hashes the same, and `parameters` (a `std::map`, already key-ordered
/// regardless of insertion order) contributes in that canonical key order —
/// so two callers who built the same parameter set via different insertion
/// sequences get the identical hash, and changing any single component
/// (including one parameter value) changes it. Returns a 32-character
/// lowercase hex digest (two concatenated 64-bit FNV-1a lanes).
[[nodiscard]] inline std::string
compute_plan_hash(std::string_view plugin, std::string_view action,
                  const std::map<std::string, std::string>& parameters,
                  std::string_view target_arm, std::string_view execution_id) {
    // Field separator (0x1f, ASCII "unit separator") so no plausible
    // plugin/action/parameter/target/execution-id value can forge a
    // collision by shifting a delimiter — none of those values legitimately
    // contain a control character.
    static constexpr char kSep = '\x1f';

    std::string canon;
    canon.reserve(plugin.size() + action.size() + target_arm.size() + execution_id.size() + 64);
    canon.append(plugin);
    canon.push_back(kSep);
    canon.append(action);
    canon.push_back(kSep);
    for (const auto& [key, value] : parameters) {
        // std::map iterates in key order irrespective of insertion order —
        // the whole of this function's order-invariance contract rests on
        // that guarantee, not on anything done here.
        canon.append(key);
        canon.push_back('=');
        canon.append(value);
        canon.push_back(kSep);
    }
    canon.append(target_arm);
    canon.push_back(kSep);
    canon.append(execution_id);

    using namespace command_capability_detail;
    const uint64_t lane_a = fnv1a(kFnvOffsetLaneA, canon, kFnvPrimeLaneA);
    const uint64_t lane_b = fnv1a(kFnvOffsetLaneB, canon, kFnvPrimeLaneB);
    return to_hex_lower_u64(lane_a) + to_hex_lower_u64(lane_b);
}

// ── The frozen v1 dispatch-tag wire grammar ──────────────────────────────
//
// `v1|<class>|<mutability>|<plan_hash_hex>`, class in {ro,mut,dest},
// mutability in {none,rev,irrev}. FROZEN: p3 mirrors this exact grammar into
// the proto comment and p8 puts it on the wire — encode/decode here is the
// one place that gets to change the spelling.

[[nodiscard]] constexpr std::string_view dispatch_class_wire(DispatchClass c) noexcept {
    switch (c) {
        case DispatchClass::ReadOnly: return "ro";
        case DispatchClass::Mutating: return "mut";
        case DispatchClass::Destructive: return "dest";
    }
    return "";
}

[[nodiscard]] constexpr std::string_view mutability_wire(Mutability m) noexcept {
    switch (m) {
        case Mutability::None: return "none";
        case Mutability::Reversible: return "rev";
        case Mutability::Irreversible: return "irrev";
    }
    return "";
}

/// One decoded dispatch tag. `plan_hash` owns its bytes (unlike the wire
/// grammar's other two fields, which are fixed small enumerations) since a
/// decoded tag typically outlives the buffer it was parsed from.
struct DispatchTag {
    DispatchClass dispatch_class;
    Mutability mutability;
    std::string plan_hash;
};

[[nodiscard]] inline bool operator==(const DispatchTag& lhs, const DispatchTag& rhs) noexcept {
    return lhs.dispatch_class == rhs.dispatch_class && lhs.mutability == rhs.mutability &&
           lhs.plan_hash == rhs.plan_hash;
}

enum class DispatchTagError : uint8_t {
    Malformed,
};

[[nodiscard]] inline std::string encode_dispatch_tag(DispatchClass dispatch_class,
                                                      Mutability mutability,
                                                      std::string_view plan_hash) {
    std::string out;
    out.reserve(plan_hash.size() + 16);
    out.append("v1");
    out.push_back('|');
    out.append(dispatch_class_wire(dispatch_class));
    out.push_back('|');
    out.append(mutability_wire(mutability));
    out.push_back('|');
    out.append(plan_hash);
    return out;
}

/// Parses EXACTLY the grammar above. Fails closed on anything else: a
/// missing/extra `|`-delimited field, a version prefix other than `v1`, an
/// unrecognized class/mutability token, an embedded newline anywhere in the
/// tag, or a `plan_hash` field containing anything outside `[0-9a-f]` — a
/// corrupted or attacker-influenced tag must never silently coerce into a
/// plausible-looking `DispatchTag`.
[[nodiscard]] inline std::expected<DispatchTag, DispatchTagError>
decode_dispatch_tag(std::string_view tag) {
    if (tag.find('\n') != std::string_view::npos)
        return std::unexpected(DispatchTagError::Malformed);

    // Split on '|' into exactly 4 fields. An embedded extra '|' — e.g. a
    // corrupted or maliciously extended plan_hash field — must be rejected
    // outright, not silently folded into (or truncating) the last field.
    std::array<std::string_view, 4> fields{};
    std::size_t field_count = 0;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= tag.size(); ++i) {
        if (i == tag.size() || tag[i] == '|') {
            if (field_count >= fields.size())
                return std::unexpected(DispatchTagError::Malformed);
            fields[field_count++] = tag.substr(start, i - start);
            start = i + 1;
        }
    }
    if (field_count != fields.size())
        return std::unexpected(DispatchTagError::Malformed);

    if (fields[0] != "v1")
        return std::unexpected(DispatchTagError::Malformed);

    DispatchClass dispatch_class;
    if (fields[1] == "ro")
        dispatch_class = DispatchClass::ReadOnly;
    else if (fields[1] == "mut")
        dispatch_class = DispatchClass::Mutating;
    else if (fields[1] == "dest")
        dispatch_class = DispatchClass::Destructive;
    else
        return std::unexpected(DispatchTagError::Malformed);

    Mutability mutability;
    if (fields[2] == "none")
        mutability = Mutability::None;
    else if (fields[2] == "rev")
        mutability = Mutability::Reversible;
    else if (fields[2] == "irrev")
        mutability = Mutability::Irreversible;
    else
        return std::unexpected(DispatchTagError::Malformed);

    const std::string_view hash = fields[3];
    if (hash.empty())
        return std::unexpected(DispatchTagError::Malformed);
    for (char c : hash) {
        const bool lower_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!lower_hex)
            return std::unexpected(DispatchTagError::Malformed);
    }

    return DispatchTag{dispatch_class, mutability, std::string(hash)};
}

} // namespace yuzu::server
