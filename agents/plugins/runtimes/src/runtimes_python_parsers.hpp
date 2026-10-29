/**
 * runtimes_python_parsers.hpp -- the PURE decision layer of the runtimes plugin's `python` action.
 *
 * Free functions over plain text, no OS call, no platform header: compiled and unit-tested on every
 * OS (tests/unit/test_runtimes_python_parsers.cpp). The three OS legs only collect the inputs.
 *
 * WHAT EACH OS KNOWS (metadata only, ZERO SUBPROCESS: no `python --version` is ever run):
 *   Windows  PEP 514 `HKLM\SOFTWARE\Python\PythonCore\<tag>`: `Version` (x.y.z), `SysVersion` (x.y),
 *            `InstallPath` default value. Both registry views; per-user hives are never read.
 *   macOS    the python.org framework `Versions/<x.y>/Resources/Info.plist`: CFBundleVersion is the
 *            full x.y.z.
 *   Linux    only the file name `python3.<minor>`: the version is major.minor, the PATCH LEVEL IS NOT
 *            AVAILABLE without running the interpreter, and no row guesses one.
 *
 * Row: python|<flavour>|<version>|<install_path>|<vendor or ->   (runtimes_parsers.hpp grammar).
 *   flavour  cpython | unmodelled     fixed vocabulary, emitted verbatim
 */
#pragma once

#include "runtimes_parsers.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace yuzu::runtimes {

enum class PythonFlavour { cpython, unmodelled };

[[nodiscard]] constexpr std::string_view flavour_token(PythonFlavour f) noexcept {
    switch (f) {
    case PythonFlavour::cpython:    return "cpython";
    case PythonFlavour::unmodelled: return "unmodelled";
    }
    return "unmodelled";
}

namespace detail {

/// `<digits>(.<digits>){dots}` exactly: no suffix, no sign, no whitespace.
[[nodiscard]] inline bool dotted_digits(std::string_view v, int dots) noexcept {
    std::size_t i = 0;
    for (int part = 0; part <= dots; ++part) {
        const std::size_t start = i;
        while (i < v.size() && is_digit(v[i])) ++i;
        if (i == start) return false;
        if (part < dots) {
            if (i >= v.size() || v[i] != '.') return false;
            ++i;
        }
    }
    return i == v.size();
}

} // namespace detail

/// `^\d+\.\d+$`
[[nodiscard]] inline bool looks_like_major_minor(std::string_view v) noexcept {
    return detail::dotted_digits(v, 1);
}

/// `^\d+\.\d+\.\d+$` -- "3.12.4rc1" and "3.12.4, (c) ..." are not full versions.
[[nodiscard]] inline bool looks_like_full_version(std::string_view v) noexcept {
    return detail::dotted_digits(v, 2);
}

// -- Linux ----------------------------------------------------------------------------

/// "3.<minor>" for exactly `python3.<digits>`; nullopt for `python3`, `python3.12-config`,
/// `python3.12m`, `python2.7`, `python312`.
[[nodiscard]] inline std::optional<std::string> python3_minor_from_name(std::string_view name) {
    constexpr std::string_view prefix = "python3.";
    if (name.size() <= prefix.size() || name.substr(0, prefix.size()) != prefix) return std::nullopt;
    const auto minor = name.substr(prefix.size());
    if (!std::all_of(minor.begin(), minor.end(), detail::is_digit)) return std::nullopt;
    return std::string{"3."} + std::string{minor};
}

// -- macOS ----------------------------------------------------------------------------

/// The text of `<string>` that directly follows the first exact `<key>NAME</key>` of an XML property
/// list. A bounded scan over a string_view (nothing reads past the buffer; an unterminated tag is a
/// miss); a value carrying an entity or a control character is not returned. nullopt for a binary
/// plist (`bplist00`), a missing key, or a key whose value is not a `<string>`. Not a plist
/// tokenizer: the first textual match wins even inside a comment or a nested dict. Accepted: the
/// framework directory is admin-writable only, and the caller still gates the value to a full version.
[[nodiscard]] inline std::optional<std::string> plist_string_value(std::string_view xml,
                                                                   std::string_view key) {
    if (xml.substr(0, 8) == "bplist00") return std::nullopt;
    std::string needle = "<key>";
    needle.append(key);
    needle += "</key>";
    const auto k = xml.find(needle);
    if (k == std::string_view::npos) return std::nullopt;
    auto rest = detail::trim(xml.substr(k + needle.size()));
    constexpr std::string_view open = "<string>";
    if (rest.substr(0, open.size()) != open) return std::nullopt;
    rest.remove_prefix(open.size());
    const auto end = rest.find("</string>");
    if (end == std::string_view::npos) return std::nullopt;
    const auto v = rest.substr(0, end);
    if (v.find('&') != std::string_view::npos || detail::has_control_char(v)) return std::nullopt;
    return std::string{v};
}

/// The full x.y.z of a framework Info.plist: CFBundleVersion, else CFBundleShortVersionString -- each
/// accepted only when the WHOLE value is a full version (the python.org plist's short string is
/// "3.13.1, (c) 2001-2024 Python Software Foundation.", which is rejected). nullopt otherwise; the
/// caller then falls back to the directory name.
[[nodiscard]] inline std::optional<std::string> python_version_from_plist(std::string_view xml) {
    for (const std::string_view key : {"CFBundleVersion", "CFBundleShortVersionString"}) {
        auto v = plist_string_value(xml, key);
        if (v && looks_like_full_version(*v)) return v;
    }
    return std::nullopt;
}

// -- Windows (PEP 514) --------------------------------------------------------------------

/// The version of one PythonCore tag: `Version` (x.y.z), else `SysVersion` (x.y), else the major.minor
/// prefix of the tag name (`3.14-32` -> `3.14`); nullopt when none of them parses.
[[nodiscard]] inline std::optional<std::string> python_version_from_pep514(
    std::string_view version_value, std::string_view sys_version_value, std::string_view tag) {
    for (const auto v : {version_value, sys_version_value}) {
        if (looks_like_full_version(v) || looks_like_major_minor(v)) return std::string{v};
    }
    // leading `<digits>.<digits>` of the tag ("3.14-32" -> "3.14"; "3.14.2" -> "3.14")
    std::size_t i = 0;
    while (i < tag.size() && detail::is_digit(tag[i])) ++i;
    if (i < tag.size() && tag[i] == '.') {
        ++i;
        while (i < tag.size() && detail::is_digit(tag[i])) ++i;
    }
    const auto prefix = tag.substr(0, i);
    if (looks_like_major_minor(prefix)) return std::string{prefix};
    return std::nullopt;
}

// -- rows ------------------------------------------------------------------------------

struct PythonRecord {
    PythonFlavour flavour = PythonFlavour::unmodelled;
    std::string version; // empty = unknown (renders `-`)
    std::string install_path;
    std::string vendor;
};

/// python|<flavour>|<version>|<install_path>|<vendor or ->
[[nodiscard]] inline std::string python_row(const PythonRecord& r) {
    return format_runtime_row("python", flavour_token(r.flavour), r.version, r.install_path, r.vendor);
}

/// One row per install path: the same path reached through both registry views keeps the FIRST
/// (the 64-bit view, which the walk visits first). Records with no path are never merged: under
/// WOW64 HKLM\SOFTWARE\Python is redirected, not shared, so only a common install path proves one
/// install; merging on tag+version could collapse a real 32-bit install into a 64-bit one.
inline void dedupe_python_rows(std::vector<PythonRecord>& recs) {
    std::vector<PythonRecord> out;
    out.reserve(recs.size());
    for (auto& r : recs) {
        const bool dup = !r.install_path.empty() &&
                         std::any_of(out.begin(), out.end(), [&](const PythonRecord& o) {
                             return o.install_path == r.install_path;
                         });
        if (!dup) out.push_back(std::move(r));
    }
    recs = std::move(out);
}

/// Stable output order for a walk whose enumeration order is not (RegEnumKeyEx is documented as
/// unordered): by version string, then install path, plain byte order like the Linux/macOS legs'
/// name-sorted listings. Run it AFTER dedupe_python_rows, so which view's record survives a
/// duplicate never depends on the sort.
inline void sort_python_rows(std::vector<PythonRecord>& recs) {
    std::stable_sort(recs.begin(), recs.end(), [](const PythonRecord& a, const PythonRecord& b) {
        return std::tie(a.version, a.install_path) < std::tie(b.version, b.install_path);
    });
}

} // namespace yuzu::runtimes
