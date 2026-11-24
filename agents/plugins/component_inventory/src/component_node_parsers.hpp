#pragma once

/**
 * component_node_parsers.hpp — pure parsers for Node package inventory.
 *
 * Header-only, no I/O: the directory walk and the file read are the scan's.
 * A package is `.../node_modules/<name>/package.json` or
 * `.../node_modules/@<scope>/<name>/package.json`; only the declared `name`
 * and `version` are read, nothing else in the file (no dependencies, scripts,
 * or any other key).
 *
 * package.json is untrusted file content: it is size-capped, parsed only with
 * nlohmann's non-throwing form (no exception can escape for any input), and
 * rejected when nested past kMaxJsonDepth levels.
 */

#include <nlohmann/json.hpp>

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::component_inventory {

/// A directory tree this many node_modules deep is not walked (npm hoists, so real trees stay shallow).
inline constexpr std::size_t kMaxNodeNesting = 8;

/// Largest package.json read; a bigger file is oversized, not truncated.
inline constexpr std::size_t kMaxPackageJsonBytes = 64 * 1024;

/// A package.json nested deeper than this many arrays/objects is too_deep.
inline constexpr int kMaxJsonDepth = 64;

inline constexpr std::size_t kMaxNodeNameBytes = 256;
inline constexpr std::size_t kMaxNodeVersionBytes = 128;

struct NodeMeta {
    std::string name;    ///< '' when absent or invalid
    std::string version; ///< '' when absent or invalid
};

enum class NodeDefect { oversized, not_json, not_object, too_deep };

enum class NodeVersionSource { package_json, unreadable };

[[nodiscard]] constexpr std::string_view to_token(NodeVersionSource s) noexcept {
    return s == NodeVersionSource::package_json ? "package_json" : "unreadable";
}

struct NodeComponent {
    std::string name;
    std::string version; ///< '' unless package.json declares a valid one
    NodeVersionSource version_source{NodeVersionSource::unreadable};
};

namespace node_detail {

inline constexpr std::string_view kNodeModules = "node_modules";

/// Non-empty '/'-separated components of `path`.
[[nodiscard]] inline std::vector<std::string_view> split(std::string_view path) {
    std::vector<std::string_view> out;
    while (!path.empty()) {
        const auto s = path.find('/');
        const auto part = path.substr(0, s);
        if (!part.empty())
            out.push_back(part);
        if (s == std::string_view::npos)
            break;
        path.remove_prefix(s + 1);
    }
    return out;
}

[[nodiscard]] inline std::size_t count_node_modules(const std::vector<std::string_view>& c) noexcept {
    std::size_t n = 0;
    for (auto p : c)
        n += p == kNodeModules ? 1 : 0;
    return n;
}

/// A package directory name: not hidden, not a scope, not node_modules itself.
[[nodiscard]] constexpr bool is_package_name(std::string_view n) noexcept {
    return !n.empty() && n.front() != '.' && n.front() != '@' && n != kNodeModules;
}

[[nodiscard]] constexpr bool is_scope_name(std::string_view n) noexcept {
    return n.size() > 1 && n.front() == '@';
}

/// The package directory that ends the first `len` components, as `<name>` or `@<scope>/<name>`
/// (empty when they do not end at one).
[[nodiscard]] inline std::string package_dir_at(const std::vector<std::string_view>& c, std::size_t len) {
    if (len >= 2 && c[len - 2] == kNodeModules && is_package_name(c[len - 1]))
        return std::string{c[len - 1]};
    if (len >= 3 && c[len - 3] == kNodeModules && is_scope_name(c[len - 2]) &&
        is_package_name(c[len - 1]))
        return std::string{c[len - 2]} + '/' + std::string{c[len - 1]};
    return {};
}

/// Control bytes (C0 and DEL) are never legal in a name or version.
[[nodiscard]] constexpr bool is_clean(std::string_view s) noexcept {
    for (char ch : s) {
        const auto u = static_cast<unsigned char>(ch);
        if (u < 0x20 || u == 0x7F)
            return false;
    }
    return true;
}

/// A string-valued `key` of `obj`, kept only when within `max_bytes` and free of control bytes.
[[nodiscard]] inline std::string string_field(const nlohmann::json& obj, const char* key, std::size_t max_bytes) {
    const auto it = obj.find(key);
    if (it == obj.end() || !it->is_string())
        return {};
    const auto& s = it->get_ref<const std::string&>();
    return s.size() <= max_bytes && is_clean(s) ? s : std::string{};
}

} // namespace node_detail

/// The package directory name (`<name>` or `@<scope>/<name>`) a `.../node_modules/.../package.json`
/// path names; nullopt for any other path (`app/package.json`, `node_modules/@scope/package.json`, a
/// hidden package name).
[[nodiscard]] inline std::optional<std::string> node_package_from_path(std::string_view path) {
    using namespace node_detail;
    const auto c = split(path);
    if (c.size() < 3 || c.back() != "package.json")
        return std::nullopt;
    auto dir = package_dir_at(c, c.size() - 1);
    if (dir.empty())
        return std::nullopt;
    return dir;
}

/// True when the walk must not descend into `dir_path`: a directory inside a package directory other
/// than a nested node_modules (src, lib, dist are never listed), `.bin`, and anything deeper than
/// kMaxNodeNesting node_modules.
[[nodiscard]] inline bool node_dir_prunable(std::string_view dir_path) {
    using namespace node_detail;
    const auto c = split(dir_path);
    if (c.empty())
        return false;
    if (count_node_modules(c) > kMaxNodeNesting || c.back() == ".bin")
        return true;
    if (c.back() == kNodeModules)
        return false;
    return !package_dir_at(c, c.size() - 1).empty();
}

/// Declared name and version of a package.json. A missing or unusable name/version is '' (not a defect);
/// a document that is not a readable JSON object is.
[[nodiscard]] inline std::expected<NodeMeta, NodeDefect> parse_package_json(std::string_view text) {
    using json = nlohmann::json;
    if (text.size() > kMaxPackageJsonBytes)
        return std::unexpected{NodeDefect::oversized};
    bool too_deep = false;
    // Returning false from the callback only discards that value; it does not stop the parse. So the
    // flag, not what survives, decides too_deep. The callback depth is the parent's: a document with
    // N arrays/objects nested inside one another starts its deepest at depth N-1.
    const auto j = json::parse(
        text,
        [&too_deep](int depth, json::parse_event_t ev, json&) {
            if ((ev == json::parse_event_t::object_start || ev == json::parse_event_t::array_start) &&
                depth + 1 > kMaxJsonDepth) {
                too_deep = true;
                return false;
            }
            return true;
        },
        /*allow_exceptions=*/false);
    if (too_deep)
        return std::unexpected{NodeDefect::too_deep};
    if (j.is_discarded())
        return std::unexpected{NodeDefect::not_json};
    if (!j.is_object())
        return std::unexpected{NodeDefect::not_object};
    return NodeMeta{node_detail::string_field(j, "name", kMaxNodeNameBytes),
                    node_detail::string_field(j, "version", kMaxNodeVersionBytes)};
}

/// The component for a package.json at `path` (a node_package_from_path path; any other path gives
/// an empty name). `text` is the file content, nullopt when it could not be read. The declared name
/// wins when present, else the directory name; any defect or an unreadable file gives the directory
/// name, no version and source `unreadable`.
[[nodiscard]] inline NodeComponent node_component(std::string_view path, const std::optional<std::string>& text) {
    const auto np = node_package_from_path(path);
    NodeComponent out;
    if (np)
        out.name = *np;
    if (!text)
        return out;
    const auto meta = parse_package_json(*text);
    if (!meta)
        return out;
    if (!meta->name.empty())
        out.name = meta->name;
    out.version = meta->version;
    out.version_source = NodeVersionSource::package_json;
    return out;
}

} // namespace yuzu::component_inventory
