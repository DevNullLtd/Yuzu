/**
 * hardware_estate_legs.hpp -- the `Kind` enum and string conversions for the four
 * hardware-estate actions (`chassis`, `baseboard`, `swap`, `machine_id`), shared by
 * hardware_plugin.cpp's dispatch.
 *
 * Until each leg PR lands (H.5 Windows, H.11 Linux, H.13 macOS) every leg is PLANNED: the
 * dispatch answers one `status|<action>|unsupported|<os>:planned` row through the shared
 * reporter (agents/shared/planned_leg.hpp) and the per-OS mechanism lives in the descriptor
 * table. The leg PR that fills one adds its own TU and row formatter.
 *
 * ROW SCHEMAS the legs will emit (fixed-width, "-" for an absent value; every untrusted field
 * goes through yuzu::util::safe_output_field); the columns are declared in
 * content/definitions/hardware.yaml:
 *
 *   chassis|<type>|<serial>|<asset_tag>|<source>
 *   baseboard|<vendor>|<product>|<serial>|<source>
 *   swap|<device>|<total_mb>|<used_mb>|<source>
 *   machine_id|<hash_hex>|<algorithm>|<source>
 *
 * `machine_id` carries a KEYED HASH only -- the raw id never leaves the host.
 */
#pragma once

#include <optional>
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

} // namespace yuzu::hardware::estate
