#pragma once

/// @file software_normalization_pack.hpp
/// Pure model of the software-title alias pack (SAM.4): a versioned CSV that maps
/// raw installed-software titles onto canonical products. No I/O, no store, no
/// clock - the parser, the edition-bearing alias key and the ecosystem -> purl
/// type table are all unit-testable over fixture strings.
///
/// CSV contract (one pack = one file, '#' lines are comments):
///
///   #pack_version: YYYY.MM.N
///   ecosystem,raw_name,raw_publisher,vendor,product,edition,category,cpe_product
///
///   - `ecosystem` and `raw_publisher` may be empty (wildcards, see
///     software_title_dimension.hpp for the precedence).
///   - `raw_name` is normalised with `normalize_title` and stored as the
///     edition-bearing `alias_key()`: an alias binds exactly ONE edition, there is
///     no edition wildcard (editions are distinct licensable SKUs).
///   - `edition` is the product's edition. It may be empty (an editionless
///     `raw_name` with an editioned product is a curator statement); when both it
///     and the edition token in `raw_name` are present they must agree.
///   - `category` is one of `kCategories` (empty = other).
///   - `cpe_product` is OUR OWN column (never read from the CPE resolver).
///   - No quoting: a field may not contain a comma or a double quote.
///   - Rows that share a canonical product (same vendor, product and edition) must
///     agree on `category` and `cpe_product`; a conflict is rejected, never resolved
///     by row order. `cpe_product` may not be `-` or `.`.
///   - Bounded input: the parser is the trust boundary for every pack body. A pack over
///     `kMaxPackBytes`, over `kMaxPackRows` rows, with a field over `kMaxFieldBytes`
///     or with a NUL byte anywhere is rejected. `pack_version` carries a month 01-12.
///     The normalisers' output (`normalize_title`, `normalize_vendor`, `alias_key`)
///     is baked into every stored key, so a change to any of them requires a new
///     `pack_version` (see product_registry_store.hpp).

#include "product_normalize.hpp"

#include <array>
#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server {

/// Closed category vocabulary of the title dimension.
inline constexpr std::array<std::string_view, 5> kCategories{
    "web_server", "database", "message_broker", "runtime", "other",
};

/// Upper bounds on one pack body (the seed is a few KB; these leave room for growth while
/// keeping a pack a bounded, in-memory parse and a bounded boot-time load).
inline constexpr std::size_t kMaxPackBytes = 1U << 20; ///< 1 MiB of CSV text
inline constexpr std::size_t kMaxPackRows = 5000;
/// Per field, so a key stays far below the btree row limit.
inline constexpr std::size_t kMaxFieldBytes = 256;

/// Lower bound on rows in a pack. A pack thinner than this resolves almost
/// nothing; the parser rejects it rather than ship a hollow seed.
inline constexpr std::size_t kMinSeedRows = 50;

/// One validated pack row. `raw_name` holds the normalised, edition-bearing
/// alias key and `raw_publisher` the normalised vendor (both lookup keys);
/// vendor/title/edition describe the canonical product.
struct PackRow {
    std::string ecosystem;
    std::string raw_name;
    std::string raw_publisher;
    std::string vendor;
    std::string title;
    std::string edition;
    std::string category;
    std::string cpe_product;
    std::string norm_key; ///< `products.norm_key` of the canonical product
};

struct ParsedPack {
    std::string pack_version; ///< `YYYY.MM.N`
    std::string sha256;       ///< of the full CSV body
    std::string body;         ///< the CSV text as parsed (persisted verbatim)
    std::vector<PackRow> rows;
};

/// The normalised title with its extracted edition re-appended
/// (`sql server standard`). Idempotent under `normalize_title`.
[[nodiscard]] inline std::string alias_key(const NormalizedTitle& nt) {
    return nt.edition.empty() ? nt.title : nt.title + ' ' + nt.edition;
}

/// Parse and validate a pack. The error string names the first defect (with its
/// line number where one applies).
[[nodiscard]] std::expected<ParsedPack, std::string> parse_normalization_pack(std::string_view csv);

/// Package-URL type for an ecosystem; empty when no purl type exists
/// (windows/msi/macos/macos_pkgutil/snap/flatpak/optional_feature).
[[nodiscard]] constexpr std::string_view purl_type_for(std::string_view ecosystem) noexcept {
    if (ecosystem == "rpm")
        return "rpm";
    if (ecosystem == "deb")
        return "deb";
    if (ecosystem == "apk")
        return "apk";
    if (ecosystem == "pacman")
        return "alpm";
    if (ecosystem == "brew")
        return "brew";
    return {};
}

/// Build-embedded provisional seed (content/software-normalization/aliases.csv).
extern const std::string_view kSoftwareNormalizationSeed;

} // namespace yuzu::server
