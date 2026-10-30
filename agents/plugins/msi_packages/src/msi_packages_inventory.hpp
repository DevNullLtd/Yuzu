/**
 * msi_packages_inventory.hpp -- pure row builder for msi_packages.list_inventory.
 *
 * No Windows headers: the OS boundary (MsiEnumProductsExW / MsiGetProductInfoExW)
 * is injected as two callables, so the builder is unit-tested on every OS from a
 * committed real capture.
 *
 * Wire grammar (consumed by parse_msi_packages_list_inventory_output in
 * agents/core/src/sync_source_installed_software.cpp). The status row is
 * formatted by yuzu::shared::format_status_row (agents/shared/inventory_status_row.hpp),
 * the same helper pkg_inventory uses and the collector parses with:
 *
 *   status|list_inventory|<supported|constrained|unsupported>|<tokens or ->
 *   inv|<product_code>|<name>|<version>|<publisher>      (one per product)
 *
 * The status row always leads. There is no sentinel row: zero products is
 * `status|list_inventory|supported|-` and nothing else. A property the product
 * does not have is an EMPTY token, never `-`; a property read that FAILS makes
 * the status row `constrained` (see classify_property_error).
 */
#pragma once

#include <inventory_status_row.hpp>

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::msi_packages::inventory {

/// MSIINSTALLCONTEXT_MACHINE. The Windows shell static_asserts equality with the
/// SDK constant; it is repeated here so this header needs no Windows headers.
inline constexpr unsigned kMachineContext = 4;

inline constexpr std::string_view kAction = "list_inventory";
inline constexpr std::string_view kPropName = "InstalledProductName";
inline constexpr std::string_view kPropVersion = "VersionString";
inline constexpr std::string_view kPropPublisher = "Publisher";

// Windows Installer error codes the Windows shell maps. Numeric here so this header
// needs no Windows headers; the shell static_asserts equality with the SDK values.
inline constexpr unsigned kErrorMoreData = 234;
inline constexpr unsigned kErrorUnknownProduct = 1605;
inline constexpr unsigned kErrorUnknownProperty = 1608;

/// Longest name, version or publisher (in characters) the shell will read. No real
/// product registers more; a longer value is a corrupt or planted one and fails the
/// roster instead of allocating whatever length the OS reports.
inline constexpr unsigned kMaxPropertyChars = 4096;

/// Disposition of a property read that returned neither success nor
/// ERROR_MORE_DATA. A product that simply has no such property is an EMPTY value
/// (measured: an unset-but-recognised property returns success with an empty
/// string, an absent one returns ERROR_UNKNOWN_PROPERTY, an unknown product
/// ERROR_UNKNOWN_PRODUCT); any other code is a failed read and becomes a token, so
/// it can never read as an absent one.
[[nodiscard]] inline std::expected<std::string, std::string> classify_property_error(
    unsigned rc) {
    if (rc == kErrorUnknownProduct || rc == kErrorUnknownProperty)
        return std::string{};
    return std::unexpected("windows:msi_prop:" + std::to_string(rc));
}

/// Buffer capacity in characters, NUL included, for the retry after
/// ERROR_MORE_DATA, given the reported length (which excludes the NUL), or the
/// failure token when the value is implausibly long.
[[nodiscard]] inline std::expected<std::size_t, std::string> retry_capacity(unsigned reported) {
    if (reported > kMaxPropertyChars)
        return std::unexpected(std::string{"windows:msi_prop:oversized"});
    return static_cast<std::size_t>(reported) + 1;
}

struct Product {
    std::string code;
    std::string name;
    std::string version;
    std::string publisher;
};

struct Inventory {
    std::vector<Product> products;
    /// Set when the enumeration did not end cleanly or a property read failed: a
    /// failure token. The rows read before the failure are kept.
    std::optional<std::string> constraint;
};

/// Walks the machine-context products. `enumerate(ctx, on_code)` calls
/// on_code(std::string) once per product code and returns nullopt when the walk
/// ended cleanly, else a failure token. `property(code, ctx, name)` returns the
/// property value (empty when the product simply has no such property) or, when
/// the read FAILED, a failure token: a failed read is never reported as an absent
/// one. The first such token makes the roster constrained (the rows read are kept),
/// unless the enumeration itself failed, whose token takes priority.
///
/// An advertised-but-not-installed product is enumerated by the OS, but
/// InstalledProductName, VersionString and Publisher are installed-only
/// properties (MsiGetProductInfoEx contract: the OS answers ERROR_UNKNOWN_PRODUCT
/// or ERROR_UNKNOWN_PROPERTY, which the shell maps to an empty value), so it
/// renders `inv|{code}|||` and the collector drops the empty name. That is
/// deliberate, not an oversight.
template <class Enumerate, class Property>
Inventory collect(Enumerate&& enumerate, Property&& property) {
    Inventory inv;
    std::optional<std::string> property_failure;
    auto read = [&](const std::string& code, std::string_view prop) {
        std::expected<std::string, std::string> r = property(code, kMachineContext, prop);
        if (r)
            return std::move(*r);
        if (!property_failure)
            property_failure = std::move(r.error());
        return std::string{};
    };
    auto on_code = [&](std::string code) {
        Product p;
        p.name = read(code, kPropName);
        p.version = read(code, kPropVersion);
        p.publisher = read(code, kPropPublisher);
        p.code = std::move(code);
        inv.products.push_back(std::move(p));
    };
    inv.constraint = enumerate(kMachineContext, on_code);
    if (!inv.constraint)
        inv.constraint = std::move(property_failure);
    return inv;
}

/// Deletes the characters that would break the row framing: '|', tab, CR, LF and
/// NUL (write_output goes through a C string, so a NUL would cut the row short and
/// the collector would drop it as malformed). Backslash and everything else is
/// kept. The collector's split_tokens (sync_source_installed_software.cpp) splits on every raw '|' and never
/// unescapes, so yuzu::util::safe_output_field's `\|` would shift the fields and
/// the row would be dropped; this is the installed_apps `inv|` pipe_safe rule
/// (installed_apps_inventory.hpp). Do NOT use safe_output_field for inv fields.
inline std::string strip_row_breakers(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
        if (c == '|' || c == '\t' || c == '\r' || c == '\n' || c == '\0')
            continue;
        out.push_back(c);
    }
    return out;
}

/// inv|<code>|<name>|<version>|<publisher>; empty stays empty.
[[nodiscard]] inline std::string format_inventory_row(const Product& p) {
    std::string out = "inv|";
    out += strip_row_breakers(p.code);
    out += '|';
    out += strip_row_breakers(p.name);
    out += '|';
    out += strip_row_breakers(p.version);
    out += '|';
    out += strip_row_breakers(p.publisher);
    return out;
}

[[nodiscard]] inline std::string unsupported_status_row(std::string_view token) {
    return yuzu::shared::format_status_row(kAction, yuzu::shared::StatusLevel::unsupported, token);
}

/// Status row first (constrained iff a constraint is set), then one row per
/// product. No cap: the enumeration is OS-bounded and the collector reads one
/// past its own row cap.
[[nodiscard]] inline std::vector<std::string> render(const Inventory& inv) {
    std::vector<std::string> rows;
    rows.reserve(inv.products.size() + 1);
    if (inv.constraint)
        rows.push_back(yuzu::shared::format_status_row(
            kAction, yuzu::shared::StatusLevel::constrained, *inv.constraint));
    else
        rows.push_back(
            yuzu::shared::format_status_row(kAction, yuzu::shared::StatusLevel::supported, {}));
    for (const auto& p : inv.products)
        rows.push_back(format_inventory_row(p));
    return rows;
}

} // namespace yuzu::msi_packages::inventory
