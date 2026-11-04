#pragma once

/// @file install_type_rules.hpp
/// Pure decision core for `installed_software.install_type` (ADR-0016 Update 2026-11-04):
/// the closed install-type vocabulary and the table that derives a row's type from the
/// collector source that produced it. No libpq, no clock, no I/O.
///
/// The type is SERVER-derived, never on the wire: the agent already stamps every row with its
/// `<plugin>.<action>` source (blob slot 16), and that source decides how the software got
/// onto the machine (except that a Linux package ecosystem under `installed_apps.list_inventory`
/// reads `package_manager`, like the same row from a pre-tail agent). A row from a pre-tail
/// (v2, 12-field) agent has an empty source, so it falls back to the ecosystem. A value outside both tables is '' ("not derived"), which the
/// column's CHECK constraint admits.
///
/// SHARED FILE: sibling workstreams add their own source rows (and nothing else) as their
/// collectors join `kSoftwareSources`; the totality `static_assert` below fails the build the
/// moment a source has no row, so a new collector cannot ship with an undecided type.

#include "software_catalog_rules.hpp"

#include <algorithm>
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
[[nodiscard]] constexpr std::string_view
install_type_for_ecosystem(std::string_view ecosystem) noexcept {
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

/// The one source whose type the ecosystem refines: `installed_apps.list_inventory` also lists
/// the Linux packages (dpkg, rpm, pacman, apk), and a pre-tail agent's empty-source row of the
/// same package is `package_manager` by ecosystem, so the same package must read the same
/// either way. Every other ecosystem under this source keeps the table's `installer`.
inline constexpr std::string_view kEcosystemRefinedSource = "installed_apps.list_inventory";

[[nodiscard]] constexpr bool is_linux_package_ecosystem(std::string_view ecosystem) noexcept {
    return ecosystem == "deb" || ecosystem == "rpm" || ecosystem == "apk" || ecosystem == "pacman";
}

/// The row's install type: the source table first (the one exception is
/// `kEcosystemRefinedSource`, where a Linux package ecosystem reads `package_manager`), the
/// ecosystem fallback second, '' last.
[[nodiscard]] constexpr std::string_view install_type_for(std::string_view source,
                                                          std::string_view ecosystem) noexcept {
    if (source == kEcosystemRefinedSource && is_linux_package_ecosystem(ecosystem))
        return "package_manager";
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
    namespace sc = software_catalog;
    return std::ranges::all_of(sc::kSoftwareSources,
                               [](const auto& src) {
                                   return std::ranges::any_of(
                                       kInstallTypeBySource,
                                       [&](const auto& row) { return row.source == src.value; });
                               }) &&
           std::ranges::all_of(kInstallTypeBySource, [](const auto& row) {
               return is_install_type(row.type) &&
                      std::ranges::any_of(sc::kSoftwareSources,
                                          [&](const auto& src) { return src.value == row.source; });
           });
}

/// The ecosystem-refined source is a real collector source, its table row is `installer`, and
/// the refinement moves only the four Linux package ecosystems to `package_manager`.
[[nodiscard]] consteval bool ecosystem_refinement_well_formed() {
    namespace sc = software_catalog;
    return std::ranges::any_of(sc::kSoftwareSources,
                               [](const auto& src) { return src.value == kEcosystemRefinedSource; }) &&
           install_type_for(kEcosystemRefinedSource, "") == "installer" &&
           install_type_for(kEcosystemRefinedSource, "windows") == "installer" &&
           install_type_for(kEcosystemRefinedSource, "macos_pkgutil") == "installer" &&
           install_type_for(kEcosystemRefinedSource, "deb") == "package_manager" &&
           install_type_for(kEcosystemRefinedSource, "rpm") == "package_manager" &&
           install_type_for(kEcosystemRefinedSource, "apk") == "package_manager" &&
           install_type_for(kEcosystemRefinedSource, "pacman") == "package_manager";
}

} // namespace install_type_detail

static_assert(install_type_detail::ecosystem_refinement_well_formed(),
              "the ecosystem-refined source must be a collector source: Linux package ecosystems "
              "read package_manager, every other ecosystem keeps the table type");

static_assert(
    install_type_detail::table_total_and_well_formed(),
    "kInstallTypeBySource must have exactly one row per software_catalog::kSoftwareSources "
    "value, each naming a kInstallTypes type; add the row for a new collector source here");

} // namespace yuzu::server
