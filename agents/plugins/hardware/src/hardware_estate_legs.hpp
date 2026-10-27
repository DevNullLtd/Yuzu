/**
 * hardware_estate_legs.hpp -- seam for the four hardware-estate actions (`chassis`,
 * `baseboard`, `swap`, `machine_id`) between hardware_plugin.cpp and the three per-OS leg
 * TUs. Modelled on peripherals_legs.hpp.
 *
 * Holds (a) the `Kind` enum and its string conversions, (b) the per-OS entry-point
 * declarations, and (c) the pure row formatters for the FINAL row schemas, so the leg PRs
 * (H.5 Windows, H.11 Linux, H.13 macOS) only fill legs. Until then every leg is PLANNED and
 * answers one `status|<action>|unsupported|<os>:planned` row (agents/shared/planned_leg.hpp);
 * no leg calls a formatter yet.
 *
 * ROW SCHEMAS (fixed-width, "-" for an absent value; every untrusted field goes through
 * yuzu::util::safe_output_field):
 *
 *   chassis|<type>|<serial>|<asset_tag>|<source>
 *   baseboard|<vendor>|<product>|<serial>|<source>
 *   swap|<device>|<total_mb>|<used_mb>|<source>
 *   machine_id|<hash_hex>|<algorithm>|<source>
 *
 * `machine_id` carries a KEYED HASH only -- the raw id never leaves the host.
 */
#pragma once

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::hardware::estate {

enum class Kind { chassis, baseboard, swap, machine_id };

[[nodiscard]] constexpr std::string_view kind_name(Kind k) noexcept {
    switch (k) {
    case Kind::chassis:    return "chassis";
    case Kind::baseboard:  return "baseboard";
    case Kind::swap:       return "swap";
    case Kind::machine_id: return "machine_id";
    }
    return "chassis";
}

/// nullopt for any other action, so the caller can tell "not an estate action" from a kind.
[[nodiscard]] constexpr std::optional<Kind> parse_kind(std::string_view action) noexcept {
    if (action == "chassis") return Kind::chassis;
    if (action == "baseboard") return Kind::baseboard;
    if (action == "swap") return Kind::swap;
    if (action == "machine_id") return Kind::machine_id;
    return std::nullopt;
}

// Per-OS entry points, defined by the leg TUs (each self-gated by its own #if) and called
// only for the host OS. Each returns 0: a planned or degraded read is not a failed command.
int run_windows(yuzu::CommandContext& ctx, Kind k);
int run_linux(yuzu::CommandContext& ctx, Kind k);
int run_macos(yuzu::CommandContext& ctx, Kind k);

namespace detail {

inline void append_field(std::string& out, std::string_view v) {
    out += '|';
    out += v.empty() ? std::string{"-"} : yuzu::util::safe_output_field(v);
}

inline std::string optional_mb(std::optional<std::uint64_t> mb) {
    return mb ? std::to_string(*mb) : std::string{"-"};
}

} // namespace detail

inline std::string format_chassis_row(std::string_view type, std::string_view serial,
                                      std::string_view asset_tag, std::string_view source) {
    std::string out = "chassis";
    detail::append_field(out, type);
    detail::append_field(out, serial);
    detail::append_field(out, asset_tag);
    detail::append_field(out, source);
    return out;
}

inline std::string format_baseboard_row(std::string_view vendor, std::string_view product,
                                        std::string_view serial, std::string_view source) {
    std::string out = "baseboard";
    detail::append_field(out, vendor);
    detail::append_field(out, product);
    detail::append_field(out, serial);
    detail::append_field(out, source);
    return out;
}

inline std::string format_swap_row(std::string_view device, std::optional<std::uint64_t> total_mb,
                                   std::optional<std::uint64_t> used_mb,
                                   std::string_view source) {
    std::string out = "swap";
    detail::append_field(out, device);
    out += '|';
    out += detail::optional_mb(total_mb);
    out += '|';
    out += detail::optional_mb(used_mb);
    detail::append_field(out, source);
    return out;
}

/// `hash_hex` is the keyed hash, never the raw machine id.
inline std::string format_machine_id_row(std::string_view hash_hex, std::string_view algorithm,
                                         std::string_view source) {
    std::string out = "machine_id";
    detail::append_field(out, hash_hex);
    detail::append_field(out, algorithm);
    detail::append_field(out, source);
    return out;
}

} // namespace yuzu::hardware::estate
