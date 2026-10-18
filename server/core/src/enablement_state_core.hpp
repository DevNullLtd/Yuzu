#pragma once

/**
 * enablement_state_core.hpp — the PURE half of the durable enablement store
 * (ADR-3006, PM1.1b). No I/O, no clock, no globals: every decision the SQL shell
 * (enablement_store.cpp) makes about bytes goes through a free function here, so the unit suites cover it
 * without Postgres.
 *
 * Contents:
 *  - Provenance wire spellings. FROZEN by the first persisted row:
 *    operator | carried_over | system.
 *  - desired_hash / overlay_hash over the checked sha256_hex.
 *    A nullopt hash is a process-wide digest failure; callers abort, never skip
 *    one row.
 *  - Boundary caps for everything an untrusted peer can put in a row: rules,
 *    registration identity, report fields, anchor bytes.
 *  - The continuity anchor (<data_dir>/enablement-anchor): parse / render and the
 *    binding rule classify_continuity (a PRESENT anchor that disagrees regresses;
 *    a MISSING one is only unwitnessed).
 *  - The loader: load_rule_row re-reads a persisted rule through
 *    make_persisted_rule (shape-only unit names, stale names kept) and maps every
 *    refusal to a closed quarantine label; unresolved_units uses resolve()'s own
 *    predicate (enablement_resolver.hpp).
 *  - The plain row types the store reads and writes.
 */

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "enablement_resolver.hpp"
#include "plugin_config_parsers.hpp"
#include "sha256_hex.hpp"

namespace yuzu::server::enablement {

// -- Provenance ----------------------------------------------------------------

[[nodiscard]] constexpr std::string_view to_wire(Provenance p) {
    switch (p) {
    case Provenance::Operator: return "operator";
    case Provenance::CarriedOver: return "carried_over";
    case Provenance::System: return "system";
    }
    return "operator"; // unreachable: the switch is exhaustive
}

/// Exact, case-sensitive: any other spelling is not a provenance.
[[nodiscard]] constexpr std::optional<Provenance> parse_provenance(std::string_view s) {
    if (s == "operator")
        return Provenance::Operator;
    if (s == "carried_over")
        return Provenance::CarriedOver;
    if (s == "system")
        return Provenance::System;
    return std::nullopt;
}

// -- Hashes --------------------------------------------------------------------

/// The injection point for the digest. The default is the checked sha256_hex;
/// tests substitute a failing one to prove a failure aborts.
using HashFn = std::function<std::optional<std::string>(std::string_view)>;

[[nodiscard]] inline HashFn default_hash() {
    return [](std::string_view s) { return sha256_hex(s); };
}

/// SHA-256 of the empty string: the hash of a RESOLVED endpoint with nothing off.
/// A never-resolved row carries '' instead, so the two states differ.
inline constexpr std::string_view kEmptySetHash =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Hash of a sorted, deduped unit-name list: units joined by '\n'. Unit names
/// are identifiers and dots (is_unit_name_shape), so '\n' cannot occur inside one.
[[nodiscard]] inline std::optional<std::string>
desired_hash(std::span<const std::string> sorted_units, const HashFn& hash = default_hash()) {
    std::string joined;
    for (std::size_t i = 0; i < sorted_units.size(); ++i) {
        if (i != 0)
            joined.push_back('\n');
        joined += sorted_units[i];
    }
    return hash(joined);
}

/// Hash of the unit overlay a release shipped: every unit with its OS bits AND
/// every requirement edge. resolve() closes over the edges, so an edge-only
/// release must make every row stale exactly like a unit change. Order-independent
/// (lines are sorted).
[[nodiscard]] inline std::optional<std::string>
overlay_hash(const UnitOverlay& overlay, const HashFn& hash = default_hash()) {
    std::vector<std::string> lines;
    lines.reserve(overlay.units.size() + overlay.requirements.size());
    for (const auto& u : overlay.units)
        lines.push_back("unit|" + u.name + "|" + std::to_string(static_cast<unsigned>(u.os)));
    for (const auto& [unit, required] : overlay.requirements)
        lines.push_back("req|" + unit + "|" + required);
    std::sort(lines.begin(), lines.end());
    std::string joined;
    for (const auto& l : lines) {
        joined += l;
        joined.push_back('\n');
    }
    return hash(joined);
}

namespace detail {
[[nodiscard]] inline bool printable_ascii(std::string_view s) {
    for (const unsigned char c : s)
        if (c < 0x20 || c > 0x7e)
            return false;
    return true;
}
} // namespace detail

// -- Boundary caps -------------------------------------------------------------

inline constexpr std::size_t kMaxHostnameBytes = 256;
inline constexpr std::size_t kMaxOsBytes = 32;
inline constexpr std::size_t kMaxArchBytes = 32;
inline constexpr std::size_t kMaxAgentVersionBytes = 64;
inline constexpr std::size_t kMaxBootIdBytes = 64;

namespace detail {
[[nodiscard]] inline bool no_control_bytes(std::string_view s) {
    for (const unsigned char c : s)
        if (c < 0x20 || c == 0x7f)
            return false;
    return true;
}
} // namespace detail

/// The registration identity the durable row stores. The registry's own log fold
/// is logging-only, so the row needs its own bound: length caps and no control
/// byte in any field. An OS outside the closed vocabulary is NOT refused here; the
/// job reports it as an unknown-OS skip (resolve() faults on it).
[[nodiscard]] inline bool check_identity(std::string_view hostname, std::string_view os,
                                         std::string_view arch, std::string_view agent_version) {
    return hostname.size() <= kMaxHostnameBytes && os.size() <= kMaxOsBytes &&
           arch.size() <= kMaxArchBytes && agent_version.size() <= kMaxAgentVersionBytes &&
           detail::no_control_bytes(hostname) && detail::no_control_bytes(os) &&
           detail::no_control_bytes(arch) && detail::no_control_bytes(agent_version);
}

/// The registration-order identity of the process that observed a registration.
[[nodiscard]] inline bool check_boot_id(std::string_view boot_id) {
    return !boot_id.empty() && boot_id.size() <= kMaxBootIdBytes && detail::printable_ascii(boot_id);
}

/// A reported (epoch, counter, hash): non-negative integers and '' or exactly 64
/// lowercase hex characters.
[[nodiscard]] inline bool check_report(std::int64_t epoch, std::int64_t counter,
                                       std::string_view hash) {
    if (epoch < 0 || counter < 0)
        return false;
    if (hash.empty())
        return true;
    if (hash.size() != 64)
        return false;
    for (const char c : hash)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

inline constexpr std::size_t kMaxRules = 1000; // checked in SQL (a serialised count)
inline constexpr std::size_t kMaxUnitsPerRule = 64;
inline constexpr std::size_t kMaxSelectorBytes = 4096;
inline constexpr std::size_t kMaxAuditRefBytes = 128;

[[nodiscard]] inline std::expected<void, std::string>
check_rule_caps(std::string_view id, std::span<const std::string> units, std::string_view selector,
                std::string_view audit_ref) {
    if (!plugin_config::is_valid_identifier(id))
        return std::unexpected<std::string>("rule id is not a valid identifier (max 64 bytes)");
    if (units.size() > kMaxUnitsPerRule)
        return std::unexpected<std::string>("rule names too many units");
    if (selector.size() > kMaxSelectorBytes)
        return std::unexpected<std::string>("rule selector too long");
    if (audit_ref.size() > kMaxAuditRefBytes)
        return std::unexpected<std::string>("rule audit_ref too long");
    return {};
}

// -- The continuity anchor -----------------------------------------------------

inline constexpr std::size_t kMaxAnchorBytes = 512;

struct Anchor {
    std::string store_id;
    std::int64_t epoch{0};
    std::int64_t counter{0};
    bool operator==(const Anchor&) const = default;
};

[[nodiscard]] inline std::string render_anchor(const Anchor& a) {
    return a.store_id + "\n" + std::to_string(a.epoch) + "\n" + std::to_string(a.counter) + "\n";
}

namespace detail {
[[nodiscard]] inline bool uuid_shape(std::string_view s) {
    if (s.size() != 36)
        return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-')
                return false;
        } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline std::optional<std::int64_t> parse_decimal(std::string_view s) {
    // from_chars refuses leading whitespace and '+', consumes a leading '-' (hence the explicit
    // refusal, which also rejects "-0"), and the 18-digit cap bounds the file before parsing.
    if (s.empty() || s.size() > 18 || s[0] == '-')
        return std::nullopt;
    std::int64_t v = 0;
    const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size())
        return std::nullopt;
    return v;
}
} // namespace detail

/// Exactly three lines: a uuid-shaped store id, a numeric epoch, a numeric
/// counter; a final newline is optional and nothing may follow. Input over
/// kMaxAnchorBytes is unparseable (a file is untrusted bytes).
[[nodiscard]] inline std::optional<Anchor> parse_anchor(std::string_view text) {
    if (text.size() > kMaxAnchorBytes)
        return std::nullopt;
    std::string_view lines[3];
    std::size_t pos = 0;
    for (auto& line : lines) {
        const auto nl = text.find('\n', pos);
        if (nl == std::string_view::npos) {
            line = text.substr(pos); // the last line may lack its newline
            pos = text.size();
        } else {
            line = text.substr(pos, nl - pos);
            pos = nl + 1;
        }
    }
    if (pos != text.size())
        return std::nullopt; // trailing garbage
    if (!detail::uuid_shape(lines[0]))
        return std::nullopt;
    const auto epoch = detail::parse_decimal(lines[1]);
    const auto counter = detail::parse_decimal(lines[2]);
    if (!epoch || !counter)
        return std::nullopt;
    return Anchor{std::string(lines[0]), *epoch, *counter};
}

enum class Continuity : std::uint8_t { Ok, Unwitnessed, Regressed };

struct ContinuityVerdict {
    Continuity kind{Continuity::Ok};
    /// Closed set: anchor_missing | store_id_mismatch | store_behind (| the
    /// anchor_unparseable the store assigns to a file it cannot read).
    std::string reason;
};

/// The binding rule. A PRESENT anchor that names another store or is ahead of the
/// store regresses; a MISSING anchor is only unwitnessed (a restore onto a host
/// with no file cannot be told from a first boot); otherwise the store is at or
/// ahead of what this host last witnessed.
[[nodiscard]] inline ContinuityVerdict classify_continuity(const std::optional<Anchor>& file,
                                                           const Anchor& store) {
    if (!file)
        return {Continuity::Unwitnessed, "anchor_missing"};
    if (file->store_id != store.store_id)
        return {Continuity::Regressed, "store_id_mismatch"};
    if (file->epoch > store.epoch || (file->epoch == store.epoch && file->counter > store.counter))
        return {Continuity::Regressed, "store_behind"};
    return {Continuity::Ok, {}};
}

// -- The loader ----------------------------------------------------------------

/// A persisted rule exactly as stored.
struct RuleRow {
    std::string id;
    std::vector<std::string> units;
    std::string selector;
    std::string provenance; ///< the wire spelling
    std::string actor;
    std::string audit_ref;
    bool active{true};
    std::int64_t updated_at_ms{0};
};

/// Closed set of reasons a stored rule is refused at load.
enum class QuarantineLabel : std::uint8_t { Refused, Provenance, Caps };

[[nodiscard]] constexpr std::string_view to_label(QuarantineLabel l) {
    switch (l) {
    case QuarantineLabel::Refused: return "refused";
    case QuarantineLabel::Provenance: return "provenance";
    case QuarantineLabel::Caps: return "caps";
    }
    return "refused";
}

/// Re-read one stored rule. Provenance first, then the caps, then
/// make_persisted_rule (shape-only unit names, selector + attribute validation).
/// There is deliberately NO overlay lookup and NO known/vanished split: a unit
/// name a release removed stays in Rule.units, resolve() applies the surviving
/// units and reports the stale name in unresolved_units.
[[nodiscard]] inline std::expected<Rule, QuarantineLabel>
load_rule_row(const RuleRow& row, std::span<const std::string_view> kinds) {
    const auto prov = parse_provenance(row.provenance);
    if (!prov)
        return std::unexpected(QuarantineLabel::Provenance);
    if (!check_rule_caps(row.id, row.units, row.selector, row.audit_ref))
        return std::unexpected(QuarantineLabel::Caps);
    auto rule = make_persisted_rule(row.id, row.units, row.selector, *prov, kinds);
    if (!rule)
        return std::unexpected(QuarantineLabel::Refused);
    return std::move(*rule);
}

/// Names rules reference that the overlay knows neither as a unit nor as a
/// recorded non-unit: resolve()'s own predicate, sorted and deduped. Independent
/// of any endpoint, so it is computed once per load.
[[nodiscard]] inline std::vector<std::string> unresolved_units(std::span<const Rule> rules,
                                                               const UnitOverlay& overlay) {
    std::set<std::string> out;
    for (const auto& r : rules)
        for (const auto& name : r.units)
            if (!overlay.find(name) && !overlay.find_non_unit(name))
                out.insert(name);
    return {out.begin(), out.end()};
}

// -- Row types ----------------------------------------------------------------

struct DesiredRow {
    std::string agent_id;
    std::int64_t input_gen{0};
    std::vector<std::string> units; ///< sorted
    std::string hash;
};

struct StampRow {
    std::string agent_id;
    std::int64_t input_gen{0};
};

} // namespace yuzu::server::enablement
