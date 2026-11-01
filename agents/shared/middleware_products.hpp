#pragma once

/**
 * middleware_products.hpp -- the product table behind the middleware plugin: pure constexpr data,
 * one row per middleware product, one leg per OS, one ordered probe list per leg.
 *
 * A product is DATA, not code. The generic runner (agents/plugins/middleware/src/
 * middleware_runner.hpp) reads a leg's probes in order:
 *
 *   probes[0]   the ENUMERATOR, a kv_file probe: one absolute file holding one stanza per
 *               installation (opened by a header line); every stanza yields a candidate (name_key,
 *               path_key).
 *   probes[1..] dir_name probes: per candidate, list `<install_path>/<path>` and read the version out
 *               of a FILE NAME in it (no file content is read). The first probe whose grammar matches
 *               a name wins.
 *
 * A leg is PLANNED exactly when it has no probes. macOS is PLANNED for every product, so the plugin
 * declares one shared constant for it instead of a leg per product. Every field is a plain
 * constant: the table is checked at compile time by products_well_formed(), so a malformed row is a
 * build failure, never a runtime surprise.
 *
 * VOCABULARY GATE. tests/test_software_vocabulary_consistency.py reads the designated initialisers
 * of the `ecosystem` and `kind` fields of the table below with a regular expression. Keep them as
 * plain string literals, and keep any comment in this file from spelling either field with an equals
 * sign and a quoted value.
 */

#include <yuzu/plugin.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace yuzu::middleware {

/// How a probe reads its source.
enum class ProbeKind : std::uint8_t {
    kv_file,  ///< one absolute file of `key=value` lines, split into stanzas
    dir_name, ///< the version is a substring of a file NAME in a directory under the install path
};

/// The file-name grammar of a dir_name probe. Name == prefix + rest + suffix, rest non-empty.
enum class NameForm : std::uint8_t {
    /// rest is `-<version>` and NOTHING else: a component tag such as `IBM_MQ_GSKit-8.0.55.mqtag`
    /// never names the product.
    exact,
    /// rest is `-<version>` or `_<anything>-<version>` (the version follows the LAST '-'): the
    /// <product> part of the name may carry an edition suffix.
    product_suffix,
};

struct Probe {
    const char* id; ///< [a-z0-9_]+, unique within the leg; the `<source>` of this probe's status tokens
    ProbeKind kind;
    /// kv_file: the absolute file. dir_name: the sub-directory under a candidate's install path
    /// (a single component, no separator).
    const char* path;
    /// kv_file: the exact header line that opens a stanza.
    const char* stanza;
    const char* name_key;    ///< kv_file: the key naming the installation
    const char* path_key;    ///< kv_file: the key holding its install path
    const char* name_prefix; ///< dir_name: file-name prefix
    const char* name_suffix; ///< dir_name: file-name suffix
    NameForm name_form;      ///< dir_name: the grammar between prefix and suffix
};

struct OsLeg {
    YuzuSupportLevel support; ///< PLANNED, CONSTRAINED or SUPPORTED
    const char* mechanism;    ///< what the leg reads, for the capability descriptor
    const char* note;         ///< capability note, or nullptr
    std::span<const Probe> probes; ///< empty exactly when support is PLANNED
};

struct Product {
    const char* id;        ///< also the action name and the wire row's first field
    const char* title;     ///< the display name emitted in every row
    const char* vendor;
    const char* ecosystem; ///< the software-estate ecosystem token (server vocabulary)
    const char* kind;      ///< the software-estate kind token (server vocabulary)
    OsLeg linux;
    OsLeg windows;
};

inline constexpr const char* kPlannedNote =
    "planned; the action answers a single unsupported status row on this OS";

// -- the table ---------------------------------------------------------------------------------

/// IBM MQ on Linux: mqinst.ini names each registered installation; the product version is the file
/// name of its swidtag (`ibm.com_IBM_MQ_<edition>-<v>.swidtag`) or, on installs that ship .mqtag
/// files, `IBM_MQ-<v>.mqtag`. The component tags beside it (GSKit, JRE, ...) carry their own
/// versions and are rejected by the `exact` grammar. Every name is a captured one
/// (tests/unit/fixtures/middleware/linux/swidtag.listing); the file name carries the
/// version.release.modification level only, never a fix pack.
inline constexpr std::array<Probe, 3> kIbmMqLinuxProbes{{
    {"mqinst_ini", ProbeKind::kv_file, "/etc/opt/mqm/mqinst.ini", "Installation:", "Name",
     "FilePath", nullptr, nullptr, NameForm::exact},
    {"swidtag", ProbeKind::dir_name, "swidtag", nullptr, nullptr, nullptr, "ibm.com_IBM_MQ",
     ".swidtag", NameForm::product_suffix},
    {"mqtag", ProbeKind::dir_name, "swidtag", nullptr, nullptr, nullptr, "IBM_MQ", ".mqtag",
     NameForm::exact},
}};

inline constexpr std::array<Product, 1> kProducts{{
    {.id = "ibm_mq",
     .title = "IBM MQ",
     .vendor = "IBM",
     .ecosystem = "ibm_mq",
     .kind = "app",
     .linux = {YUZU_SUPPORT_SUPPORTED,
               "/etc/opt/mqm/mqinst.ini Installation: stanzas; version from the swidtag file name "
               "under each installation's FilePath; no dspmqver",
               nullptr, kIbmMqLinuxProbes},
     .windows = {YUZU_SUPPORT_PLANNED,
                 "HKLM\\SOFTWARE\\IBM\\WebSphere MQ\\Installation\\<name> FilePath/VRMF in both "
                 "registry views",
                 kPlannedNote, {}}},
}};

[[nodiscard]] constexpr const Product* find_product(std::string_view id) noexcept {
    for (const Product& p : kProducts)
        if (std::string_view{p.id} == id)
            return &p;
    return nullptr;
}

// -- compile-time well-formedness ----------------------------------------------------------------

namespace detail {

[[nodiscard]] constexpr std::string_view sv(const char* s) noexcept {
    return s != nullptr ? std::string_view{s} : std::string_view{};
}

/// `[a-z][a-z0-9_]*` (alpha_first) or `[a-z0-9_]+`.
[[nodiscard]] constexpr bool is_ident(std::string_view s, bool alpha_first) noexcept {
    if (s.empty())
        return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        const bool lower = c >= 'a' && c <= 'z';
        const bool digit = c >= '0' && c <= '9';
        if (!(lower || digit || c == '_'))
            return false;
        if (i == 0 && alpha_first && !lower)
            return false;
    }
    return true;
}

/// An absolute path of plain components: no trailing '/', no empty (`//`), `.` or `..` component.
/// The Linux leg refuses anything else at run time (lexically_plain in
/// agents/plugins/middleware/src/middleware_linux_parsers.hpp), which would constrain every dispatch,
/// so the table refuses it at build time.
[[nodiscard]] constexpr bool is_plain_abs_path(std::string_view s) noexcept {
    if (s.size() < 2 || s.front() != '/' || s.back() == '/')
        return false;
    std::size_t pos = 1;
    while (pos <= s.size()) {
        auto slash = s.find('/', pos);
        if (slash == std::string_view::npos)
            slash = s.size();
        const std::string_view part = s.substr(pos, slash - pos);
        if (part.empty() || part == "." || part == "..")
            return false;
        pos = slash + 1;
    }
    return true;
}

[[nodiscard]] constexpr bool enumerator_well_formed(const Probe& p) noexcept {
    return p.kind == ProbeKind::kv_file && is_plain_abs_path(sv(p.path)) &&
           !sv(p.name_key).empty() && !sv(p.path_key).empty() && !sv(p.stanza).empty();
}

[[nodiscard]] constexpr bool dir_probe_well_formed(const Probe& p) noexcept {
    const std::string_view path = sv(p.path);
    return p.kind == ProbeKind::dir_name && !path.empty() && path != "." && path != ".." &&
           path.find('/') == std::string_view::npos && path.find('\\') == std::string_view::npos &&
           !sv(p.name_prefix).empty() && !sv(p.name_suffix).empty();
}

[[nodiscard]] constexpr bool leg_well_formed(const OsLeg& leg) noexcept {
    if (leg.support != YUZU_SUPPORT_PLANNED && leg.support != YUZU_SUPPORT_CONSTRAINED &&
        leg.support != YUZU_SUPPORT_SUPPORTED)
        return false;
    if ((leg.support == YUZU_SUPPORT_PLANNED) != leg.probes.empty())
        return false;
    if (sv(leg.mechanism).empty())
        return false;
    for (std::size_t i = 0; i < leg.probes.size(); ++i) {
        const Probe& p = leg.probes[i];
        if (!is_ident(sv(p.id), /*alpha_first=*/false))
            return false;
        for (std::size_t j = 0; j < i; ++j)
            if (sv(leg.probes[j].id) == sv(p.id))
                return false;
        if (!(i == 0 ? enumerator_well_formed(p) : dir_probe_well_formed(p)))
            return false;
    }
    return true;
}

} // namespace detail

/// The invariants every table row must hold; the plugin and the runner rely on them and do not
/// re-check. Taking the table as a parameter lets a test prove that a broken one is refused.
[[nodiscard]] consteval bool products_well_formed(std::span<const Product> table) {
    for (std::size_t i = 0; i < table.size(); ++i) {
        const Product& p = table[i];
        if (!detail::is_ident(detail::sv(p.id), true) ||
            !detail::is_ident(detail::sv(p.ecosystem), true) || detail::sv(p.title).empty() ||
            detail::sv(p.vendor).empty() || detail::sv(p.kind) != "app")
            return false;
        for (std::size_t j = 0; j < i; ++j)
            if (detail::sv(table[j].id) == detail::sv(p.id) ||
                detail::sv(table[j].ecosystem) == detail::sv(p.ecosystem))
                return false;
        if (!detail::leg_well_formed(p.linux) || !detail::leg_well_formed(p.windows))
            return false;
    }
    return true;
}

[[nodiscard]] consteval bool products_well_formed() {
    return products_well_formed(std::span<const Product>{kProducts});
}

static_assert(products_well_formed(), "kProducts violates a middleware_products.hpp invariant");

} // namespace yuzu::middleware
