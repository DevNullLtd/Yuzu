#pragma once

/**
 * component_python_parsers.hpp — pure parsers for Python distribution metadata.
 *
 * Header-only, std-only, no I/O: the caller reads at most the first
 * kMaxPythonMetadataBytes of a METADATA / PKG-INFO file and hands the bytes
 * in. Every input is untrusted, so each parser is a bounded linear scan (no
 * regex) and returns nullopt on anything it cannot positively read. Names are
 * reported as declared: no case folding and no `_` to `-` normalisation.
 */

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::component_inventory {

/// The caller reads no more than this many bytes of a METADATA / PKG-INFO file.
inline constexpr std::size_t kMaxPythonMetadataBytes = 16 * 1024;
inline constexpr std::size_t kMaxPythonNameBytes = 256;
inline constexpr std::size_t kMaxPythonVersionBytes = 128;

struct PyDist {
    std::string name;
    std::string version;
};

struct PythonComponent {
    std::string name;
    std::string version;
    std::string version_source; ///< "metadata" | "filename" | "unreadable"
};

namespace python_detail {

inline bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
}

inline char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

inline bool iequals_prefix(std::string_view s, std::string_view prefix_lower) {
    if (s.size() < prefix_lower.size())
        return false;
    for (std::size_t i = 0; i < prefix_lower.size(); ++i)
        if (lower(s[i]) != prefix_lower[i])
            return false;
    return true;
}

inline std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

/// A value is usable when non-empty, within `max` bytes and free of control bytes.
inline bool valid_value(std::string_view v, std::size_t max) {
    if (v.empty() || v.size() > max)
        return false;
    for (const unsigned char c : v)
        if (c < 0x20 || c == 0x7F)
            return false;
    return true;
}

inline std::string_view leaf_of(std::string_view path) {
    const auto p = path.find_last_of("/\\");
    return p == std::string_view::npos ? path : path.substr(p + 1);
}

/// `<name>-<version>` stem split at the first '-' followed by a digit.
inline std::optional<PyDist> split_stem(std::string_view stem) {
    for (std::size_t i = 1; i + 1 < stem.size(); ++i) {
        if (stem[i] == '-' && stem[i + 1] >= '0' && stem[i + 1] <= '9') {
            return PyDist{std::string(stem.substr(0, i)), std::string(stem.substr(i + 1))};
        }
    }
    return std::nullopt;
}

} // namespace python_detail

/// METADATA (dist-info), PKG-INFO (egg-info dir) or a single-file `*.egg-info`.
inline bool is_python_metadata_leaf(std::string_view leaf) {
    return leaf == "METADATA" || leaf == "PKG-INFO" || python_detail::ends_with(leaf, ".egg-info");
}

/// `<name>-<version>.dist-info`, `<name>-<version>.egg-info`, `<name>-<version>-py<X.Y>.egg-info`.
inline std::optional<PyDist> python_dist_from_dir(std::string_view dir_leaf) {
    using python_detail::ends_with;
    std::string_view stem;
    if (ends_with(dir_leaf, ".dist-info"))
        stem = dir_leaf.substr(0, dir_leaf.size() - 10);
    else if (ends_with(dir_leaf, ".egg-info"))
        stem = dir_leaf.substr(0, dir_leaf.size() - 9);
    else
        return std::nullopt;
    auto d = python_detail::split_stem(stem);
    if (!d)
        return std::nullopt;
    if (ends_with(dir_leaf, ".egg-info")) {
        // Drop the `-py<X.Y>` interpreter tag; the version is what precedes it.
        const auto p = d->version.rfind("-py");
        if (p != std::string::npos && p + 3 < d->version.size() && d->version[p + 3] >= '0' &&
            d->version[p + 3] <= '9')
            d->version.resize(p);
    }
    if (d->name.empty() || d->version.empty())
        return std::nullopt;
    return d;
}

/// The directory leaf that owns a METADATA / PKG-INFO path, or the leaf itself for a
/// single-file `.egg-info`; nullopt when the parent is not a matching directory.
inline std::optional<std::string_view> python_metadata_owner(std::string_view path) {
    using python_detail::ends_with;
    const auto leaf = python_detail::leaf_of(path);
    if (ends_with(leaf, ".egg-info"))
        return leaf;
    const bool is_meta = leaf == "METADATA";
    if (!is_meta && leaf != "PKG-INFO")
        return std::nullopt;
    const auto dir = path.substr(0, path.size() - leaf.size());
    if (dir.empty())
        return std::nullopt;
    const auto trimmed = dir.substr(0, dir.size() - 1); // drop the separator
    const auto parent = python_detail::leaf_of(trimmed);
    if (is_meta ? ends_with(parent, ".dist-info") : ends_with(parent, ".egg-info"))
        return parent;
    return std::nullopt;
}

/// First `Name:` and `Version:` header of `head` (header block only, up to the first blank line).
inline std::optional<PyDist> parse_python_metadata(std::string_view head) {
    using namespace python_detail;
    if (head.size() > kMaxPythonMetadataBytes)
        head = head.substr(0, kMaxPythonMetadataBytes);
    std::optional<std::string_view> name, version;
    std::size_t pos = 0;
    while (pos < head.size()) {
        auto eol = head.find('\n', pos);
        auto line = head.substr(pos, eol == std::string_view::npos ? std::string_view::npos : eol - pos);
        pos = eol == std::string_view::npos ? head.size() : eol + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (line.empty())
            break; // end of headers; the body is never read
        if (line.front() == ' ' || line.front() == '\t')
            continue; // continuation line
        if (!name && iequals_prefix(line, "name:"))
            name = trim(line.substr(5));
        else if (!version && iequals_prefix(line, "version:"))
            version = trim(line.substr(8));
    }
    if (!name || !version || !valid_value(*name, kMaxPythonNameBytes) ||
        !valid_value(*version, kMaxPythonVersionBytes))
        return std::nullopt;
    return PyDist{std::string(*name), std::string(*version)};
}

/// Resolve a component for a metadata candidate `path`; `head` is the file's leading bytes
/// when it could be read.
inline PythonComponent python_component(std::string_view path, std::optional<std::string_view> head) {
    if (head) {
        if (auto d = parse_python_metadata(*head))
            return {std::move(d->name), std::move(d->version), "metadata"};
    }
    const auto owner = python_metadata_owner(path);
    if (owner) {
        if (auto d = python_dist_from_dir(*owner))
            return {std::move(d->name), std::move(d->version), "filename"};
    }
    return {std::string(owner ? *owner : python_detail::leaf_of(path)), "", "unreadable"};
}

} // namespace yuzu::component_inventory
