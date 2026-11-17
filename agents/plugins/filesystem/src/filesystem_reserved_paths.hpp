#pragma once

/// @file filesystem_reserved_paths.hpp
/// WP06 F55: paths the filesystem plugin REFUSES because they hold the agent's own control-plane
/// secrets. `filesystem.read` / `search` / `get_acl` / `file_hash` are authorized by
/// `FileRetrieval:Read` with no execute gate, while the same bytes (the agent log, which has
/// carried the session credential; the mTLS key; the data directory) are reachable through
/// `agent_logging.get_log` / `status` / `diagnostics` only under `PluginSecret`. So the plugin
/// itself refuses: an agent-owned path is never readable through `FileRetrieval`.
///
/// Pure (no I/O): the plugin canonicalises the configured paths once at init
/// (`agent.data_dir`, `agent.cert_dir`, `agent.log_file`, `agent.tls_*`) and canonicalises each
/// request path with symlinks resolved before asking. CONFINEMENT IS BEST EFFORT against a writer
/// who controls a parent directory (a check-then-open window remains); it is not absolute and
/// must not be described as such. Matching is segment-boundary, never a bare prefix; on Windows
/// it is ASCII-case-insensitive.

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::filesystem::reserved {

struct Set {
    std::vector<std::string> dirs;  ///< the directory itself and everything under it
    std::vector<std::string> files; ///< the file, and `<file>.<suffix>` siblings (log rotation)

    [[nodiscard]] bool empty() const noexcept { return dirs.empty() && files.empty(); }
};

/// Normalise for comparison: '\' -> '/', collapse a trailing '/', fold ASCII case on Windows.
[[nodiscard]] inline std::string normalise(std::string_view p) {
    std::string out;
    out.reserve(p.size());
    for (char c : p) {
        char n = c == '\\' ? '/' : c;
#ifdef _WIN32
        if (n >= 'A' && n <= 'Z')
            n = static_cast<char>(n - 'A' + 'a');
#endif
        out.push_back(n);
    }
    while (out.size() > 1 && out.back() == '/')
        out.pop_back();
    return out;
}

/// True when `canonical_path` (symlinks already resolved by the caller) names a reserved dir,
/// something under one, or a reserved file (or its rotated sibling `<file>.<suffix>`).
[[nodiscard]] inline bool is_agent_reserved_path(const Set& set, std::string_view canonical_path) {
    if (canonical_path.empty())
        return false;
    const std::string p = normalise(canonical_path);
    for (const auto& raw : set.dirs) {
        const std::string d = normalise(raw);
        if (d.empty())
            continue;
        if (p == d)
            return true;
        const std::string prefix = d == "/" ? d : d + "/";
        if (p.size() > prefix.size() && p.compare(0, prefix.size(), prefix) == 0)
            return true;
    }
    for (const auto& raw : set.files) {
        const std::string f = normalise(raw);
        if (f.empty())
            continue;
        if (p == f)
            return true;
        if (p.size() > f.size() && p.compare(0, f.size(), f) == 0 && p[f.size()] == '.')
            return true;
    }
    return false;
}

} // namespace yuzu::filesystem::reserved
