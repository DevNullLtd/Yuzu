#pragma once

/// @file purl_compose.hpp
/// Pure composer for the `installed_software.purl` column (ADR-0016 Update 2026-11-04): a Package
/// URL built SERVER-SIDE from fields the blob already carries. Nothing is on the wire and the
/// purl enters neither hash. No store, no clock, no I/O; total and never throwing.
///
/// Reference: the Package-URL specification (ECMA-427, purl-spec repository `docs/specification/
/// standard`, Clause 5 "Package-URL Specification", sections 5.4 character encoding and 5.6
/// component rules; `docs/specification/how-to-build.md` for the build order) and the type
/// definitions under `types/` (`alpm`, `apk`, `brew`, `deb`, `rpm`), each checked against its
/// `tests/types/<type>-test.json` vectors (test_purl_compose.cpp carries the build vectors).
///
/// Shape: `pkg:<type>/<namespace>/<name>@<version>?<qualifiers>`.
///   - type: lowercase, from `purl_type_for` (the SAM.4 ecosystem -> type table, the one source).
///     An ecosystem with no registered type (windows, macos, macos_pkgutil, msi, snap, flatpak,
///     optional_feature, python, ibm_mq) yields ''. A type is never invented: `python` rows are
///     interpreter installs (`runtimes.python`), not PyPI distributions, so they stay ''.
///   - namespace, name, version, qualifier values: UTF-8 bytes percent-encoded (uppercase hex)
///     except `A-Z a-z 0-9 . - _ ~` and ':' (spec 5.2 / 5.4: ':' is never encoded; '+' '@' '/'
///     ' ' '?' '#' are). Namespace segments are encoded one by one; a distro id is ONE segment.
///   - qualifiers: lowercase keys, empty values dropped, sorted by key (so `arch` before
///     `distro` before `epoch`), joined with '&'.
///
/// Per ecosystem (the table in ADR-0016 Update 2026-11-04 repeats it):
///   deb   pkg:deb/<distro_id>/<name>@[<epoch>:]<version>[-<revision>]?arch=&distro=
///   rpm   pkg:rpm/<distro_id>/<name>@<version>[-<release>]?arch=&distro=&epoch=
///         (epoch is a qualifier for rpm, a version prefix for deb and alpm: the type
///         definitions say so; the rpm name keeps its case, every other type lowercases it)
///   apk   pkg:apk/<distro_id>/<name>@<version>[-r<pkgrel>]?arch=&distro=
///         (`release` holds pkgrel WITHOUT apk's display 'r'; the composer restores it)
///   alpm  pkg:alpm/<distro_id>/<name>@[<epoch>:]<pkgver>[-<pkgrel>]?arch=
///         (rolling: the spec lists only `arch`, so no distro qualifier)
///   brew  formula: pkg:brew/<name>@<version>      (default tap, the spec's own vector form;
///         no qualifiers: the type defines only repository_url, so arch is not emitted)
///         cask:    pkg:brew/homebrew/cask/<name>@<version>
///         (formula names lowercased; '@' in a name is encoded %40)
///   The Homebrew presence row (`pkg_inventory.managers`) is the package manager itself, not a
///   formula, and gets no purl.
///
/// `distro` qualifier: `<distro_id>-<distro_version>` (the rpm vector's `fedora-25` shape), only
/// when BOTH are known: an id alone is already the namespace. Where the vendor namespace is
/// required (deb, rpm, apk, alpm) and `distro_id` is empty the result is '' (the namespace
/// would have to be invented).
///
/// '' is also returned when the name or version is empty (a version-less purl names a package,
/// not an install, and would match every version) and when the result would exceed
/// kMaxPurlBytes. The cap sits below the btree tuple limit of the column's index; the composer
/// NEVER truncates, because a cut purl names a different package.

#include "software_inventory_types.hpp"
#include "software_normalization_pack.hpp" // purl_type_for

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

/// Upper bound on a composed purl. Well under the btree index tuple limit (about 2.7 kB) so the
/// partial index can never refuse a row; longer inputs get '' (they are not store-worthy names).
inline constexpr std::size_t kMaxPurlBytes = 2048;

namespace purl_detail {

[[nodiscard]] constexpr bool is_unreserved(unsigned char c) noexcept {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '-' || c == '_' || c == '~' || c == ':';
}

/// Percent-encode the UTF-8 bytes of `in` (uppercase hex), keeping the spec's unreserved set.
[[nodiscard]] inline std::string encode(std::string_view in) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size());
    for (const char ch : in) {
        const auto c = static_cast<unsigned char>(ch);
        if (is_unreserved(c)) {
            out.push_back(ch);
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0f]);
        }
    }
    return out;
}

[[nodiscard]] inline std::string ascii_lower(std::string_view in) {
    std::string out(in);
    for (char& ch : out) {
        if (ch >= 'A' && ch <= 'Z')
            ch = static_cast<char>(ch - 'A' + 'a');
    }
    return out;
}

} // namespace purl_detail

/// The purl of one installed-software row, or '' (see the file comment). Total: every input
/// yields a string, none throws except std::bad_alloc.
[[nodiscard]] inline std::string compose_purl(const SoftwareEntry& e) {
    using namespace purl_detail;
    const std::string_view type = purl_type_for(e.ecosystem);
    if (type.empty() || e.name.empty() || e.version.empty())
        return {};

    std::string ns;   // already encoded, '/'-joined
    std::string name; // already encoded
    std::string version;
    std::vector<std::pair<std::string_view, std::string>> quals; // key -> raw value, key-sorted below

    if (type == "brew") {
        if (e.source == "pkg_inventory.managers")
            return {}; // the manager's own presence row, not a formula or cask
        if (e.kind == "app")
            ns = "homebrew/cask";
        name = encode(ascii_lower(e.name));
        version = encode(e.version);
    } else {
        // deb, rpm, apk, alpm: the vendor namespace is required and is the os-release ID.
        if (e.distro_id.empty())
            return {};
        ns = encode(ascii_lower(e.distro_id));
        name = encode(type == "rpm" ? e.name : ascii_lower(e.name));
        std::string v = e.version;
        if (type == "rpm") {
            if (!e.release.empty())
                v += '-' + e.release;
            if (!e.epoch.empty())
                quals.emplace_back("epoch", e.epoch);
        } else {
            if (type != "apk" && !e.epoch.empty())
                v.insert(0, e.epoch + ':');
            if (!e.release.empty())
                v += (type == "apk" ? "-r" : "-") + e.release;
        }
        version = encode(v);
        if (type != "alpm" && !e.distro_version.empty())
            quals.emplace_back("distro", ascii_lower(e.distro_id) + '-' + e.distro_version);
    }
    // The brew type defines no `arch` qualifier (only repository_url): never invent one.
    if (type != "brew" && !e.arch.empty())
        quals.emplace_back("arch", e.arch);

    std::string out = "pkg:";
    out += type;
    out += '/';
    if (!ns.empty()) {
        out += ns;
        out += '/';
    }
    out += name;
    out += '@';
    out += version;
    // Qualifier keys are fixed lowercase literals; sort by key, then drop empty values.
    for (std::size_t i = 1; i < quals.size(); ++i) {
        for (std::size_t j = i; j > 0 && quals[j].first < quals[j - 1].first; --j)
            std::swap(quals[j], quals[j - 1]);
    }
    char sep = '?';
    for (const auto& [key, value] : quals) {
        if (value.empty())
            continue;
        out += sep;
        out += key;
        out += '=';
        out += encode(value);
        sep = '&';
    }
    return out.size() > kMaxPurlBytes ? std::string{} : out;
}

} // namespace yuzu::server
