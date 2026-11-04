#pragma once

/// @file install_type_rules.hpp
/// Pure decision core for `installed_software.install_type` (ADR-0016 Update 2026-11-04):
/// the closed install-type vocabulary and the table that derives a row's type from the
/// collector source that produced it. No libpq, no clock, no I/O.
///
/// The type is SERVER-derived, never on the wire: the agent already stamps every row with its
/// `<plugin>.<action>` source (blob slot 16), and that source decides how the software got
/// onto the machine. A row from a pre-tail (v2, 12-field) agent has an empty source, so it
/// falls back to the ecosystem. A value outside both tables is '' ("not derived"), which the
/// column's CHECK constraint admits.
///
/// SHARED FILE: sibling workstreams add their own source rows (and nothing else) as their
/// collectors join `kSoftwareSources`; the totality `static_assert` below fails the build the
/// moment a source has no row, so a new collector cannot ship with an undecided type.

#include "software_catalog_rules.hpp"

#include <array>
#include <cstddef>
#include <string_view>

namespace yuzu::server {

/// The closed `install_type` vocabulary (matches the `installed_software_install_type_chk`
/// CHECK constraint, which additionally admits '' for "not yet derived"). `driver` is reserved
/// for the drivers facet and `component` for embedded components; no source maps to either yet.
inline constexpr std::array<std::string_view, 9> kInstallTypes{{
    "msi",
    "installer",
    "store",
    "package_manager",
    "optional_feature",
    "runtime",
    "middleware",
    "component",
    "driver",
}};

struct InstallTypeRow {
    std::string_view source; ///< a software_catalog::kSoftwareSources value
    std::string_view type;   ///< a kInstallTypes value
};

/// One row per collector source. `pkg_inventory.managers` (the Homebrew presence row) is
/// stored in installed_software today, so it is typed like the packages it manages.
inline constexpr std::array<InstallTypeRow, 8> kInstallTypeBySource{{
    {"installed_apps.list_inventory", "installer"},
    {"pkg_inventory.managers", "package_manager"},
    {"pkg_inventory.packages", "package_manager"},
    {"pkg_inventory.store_packages", "store"},
    {"windows_optional_features.list", "optional_feature"},
    {"msi_packages.list_inventory", "msi"},
    {"runtimes.python", "runtime"},
    {"middleware.ibm_mq", "middleware"},
}};

/// Fallback for a row whose source is empty (a pre-tail agent) or not in the table.
[[nodiscard]] constexpr std::string_view install_type_for_ecosystem(
    std::string_view ecosystem) noexcept {
    if (ecosystem == "msi")
        return "msi";
    if (ecosystem == "optional_feature")
        return "optional_feature";
    if (ecosystem == "python")
        return "runtime";
    if (ecosystem == "ibm_mq")
        return "middleware";
    if (ecosystem == "snap" || ecosystem == "flatpak")
        return "store";
    if (ecosystem == "brew" || ecosystem == "rpm" || ecosystem == "deb" || ecosystem == "apk" ||
        ecosystem == "pacman")
        return "package_manager";
    if (ecosystem == "windows" || ecosystem == "macos" || ecosystem == "macos_pkgutil")
        return "installer";
    return {};
}

/// The row's install type: the source table first, the ecosystem fallback second, '' last.
[[nodiscard]] constexpr std::string_view install_type_for(std::string_view source,
                                                          std::string_view ecosystem) noexcept {
    for (const auto& row : kInstallTypeBySource) {
        if (row.source == source)
            return row.type;
    }
    return install_type_for_ecosystem(ecosystem);
}

[[nodiscard]] constexpr bool is_install_type(std::string_view t) noexcept {
    for (const auto v : kInstallTypes) {
        if (v == t)
            return true;
    }
    return false;
}

namespace install_type_detail {

/// Every collector source has a row, and every row names a real source and a real type.
[[nodiscard]] consteval bool table_total_and_well_formed() {
    for (const auto& src : software_catalog::kSoftwareSources) {
        bool found = false;
        for (const auto& row : kInstallTypeBySource) {
            if (row.source == src.value)
                found = true;
        }
        if (!found)
            return false;
    }
    for (const auto& row : kInstallTypeBySource) {
        if (!is_install_type(row.type))
            return false;
        bool known = false;
        for (const auto& src : software_catalog::kSoftwareSources) {
            if (src.value == row.source)
                known = true;
        }
        if (!known)
            return false;
    }
    return true;
}

} // namespace install_type_detail

static_assert(install_type_detail::table_total_and_well_formed(),
              "kInstallTypeBySource must have exactly one row per software_catalog::kSoftwareSources "
              "value, each naming a kInstallTypes type; add the row for a new collector source here");

} // namespace yuzu::server
