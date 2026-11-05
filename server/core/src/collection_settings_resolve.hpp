#pragma once

/// @file collection_settings_resolve.hpp
/// Pure core of the per-management-group software collection settings (SAM-34, roadmap 3.7a):
/// the document types, the validator, the canonical text and version hashes, and the resolver
/// that picks the one document that applies to a device. No I/O, no store, no clock: the routes
/// hand it pre-read membership, tree, stored documents and a kill-switch snapshot.
///
/// Resolution (see `resolve`):
///   - the ROOT group's document is the fleet-default LAYER, never a competing candidate: every
///     device is a member of the root group and groups created without a parent sit beside it at
///     depth 0, so a competing root document would otherwise win every created_at tie against a
///     top-level group;
///   - for each group the device belongs to, the nearest group (itself, then its ancestors,
///     excluding root) that carries a document is a candidate;
///   - a candidate whose group is an ancestor of another candidate's group is dropped (nearest
///     wins inside a branch), so priority only decides between unrelated branches;
///   - the survivor is chosen by priority (higher wins), depth (deeper wins), group created_at
///     (older wins), group id (smaller wins);
///   - no candidate: the root document if one exists, else the built-in fleet default;
///   - the kill-switch snapshot is applied last as an overlay that always wins, and the registered
///     apps collector is on unless it is itself kill-switched.
///
/// Two version hashes, both SHA-256 over a fixed-order canonical text joined with '\n':
///   - `document_version` covers the stored fields INCLUDING priority, so a priority-only edit
///     changes it and a concurrent edit is caught by `expected_version`;
///   - `effective_version` covers the resolved fields only (interval, window, zone, sorted
///     per-plugin switches with the overlay applied): no priority, source group or timestamps.

#include "sha256_hex.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace yuzu::server::collection_settings {

/// Mirror of ManagementGroupStore::kRootGroupId; the routes TU checks the two agree.
inline constexpr std::string_view kRootGroupId = "000000000000";

/// The collector plugins a document carries a switch for (agents/core/src/
/// sync_source_installed_software.cpp collector table). Sorted: this is also the canonical order.
inline constexpr std::array<std::string_view, 6> kCollectionPlugins = {
    "installed_apps", "middleware",    "msi_packages",
    "pkg_inventory",  "runtimes",      "windows_optional_features",
};
/// Registered apps collection is always on (unless kill-switched).
inline constexpr std::string_view kRegisteredAppsPlugin = "installed_apps";

inline constexpr int kMinIntervalS = 3600;        // 1 h
inline constexpr int kMaxIntervalS = 604800;      // 7 d
inline constexpr int kDayS = 86400;
inline constexpr int kMaxPriority = 1000;
inline constexpr int kMaxTimezoneBytes = 64;
inline constexpr int kMinutesPerDay = 1440;

/// Minutes past local midnight; 0 <= start_min < end_min <= 1440.
struct Window {
    int start_min{0};
    int end_min{0};
    bool operator==(const Window&) const = default;
};

/// The resolved fields (no priority).
struct EffectiveSettings {
    int interval_s{kDayS};
    std::optional<Window> window;
    std::string timezone; ///< '' = machine-local, else an IANA name the store validated
    std::map<std::string, bool> plugins;
    bool operator==(const EffectiveSettings&) const = default;
};

/// One group's stored document body.
struct CollectionSettings {
    int interval_s{kDayS};
    std::optional<Window> window;
    std::string timezone;
    std::map<std::string, bool> plugins;
    int priority{0};
    bool operator==(const CollectionSettings&) const = default;

    [[nodiscard]] EffectiveSettings effective() const {
        return EffectiveSettings{interval_s, window, timezone, plugins};
    }
};

struct StoredDocument {
    std::string group_id;
    CollectionSettings settings;
    std::string version; ///< document_version as written
    std::int64_t updated_at{0};
    std::string updated_by;
};

/// A management group as the resolver sees it.
struct GroupNode {
    std::string id;
    std::string parent_id; ///< '' = top level
    std::int64_t created_at{0};
};

struct ResolveResult {
    EffectiveSettings effective;
    std::string source_group_id; ///< '' = built-in fleet default; kRootGroupId = the root document
    std::string version;         ///< effective_version(effective)
};

/// 24 h, 01:00-05:00, machine-local, every collector on, priority 0.
inline const CollectionSettings kFleetDefault = [] {
    CollectionSettings s;
    s.interval_s = kDayS;
    s.window = Window{60, 300};
    for (const auto p : kCollectionPlugins)
        s.plugins.emplace(std::string{p}, true);
    return s;
}();

[[nodiscard]] inline bool is_collection_plugin(std::string_view name) {
    return std::ranges::find(kCollectionPlugins, name) != kCollectionPlugins.end();
}

/// Bounds and shape. `is_root` = the document belongs to the root group. The timezone check is
/// shape only; the store checks existence against the database's zone table.
[[nodiscard]] inline std::expected<void, std::string> validate(const CollectionSettings& s,
                                                               bool is_root) {
    if (s.interval_s < kMinIntervalS || s.interval_s > kMaxIntervalS)
        return std::unexpected("interval_s must be between 3600 and 604800");
    if (s.window) {
        if (s.interval_s % kDayS != 0)
            return std::unexpected("a window needs a whole-day interval (86400, 172800, ...)");
        if (s.window->start_min < 0 || s.window->end_min > kMinutesPerDay ||
            s.window->start_min >= s.window->end_min)
            return std::unexpected("window needs 0 <= start_min < end_min <= 1440");
    }
    if (s.timezone.size() > static_cast<std::size_t>(kMaxTimezoneBytes))
        return std::unexpected("timezone exceeds 64 bytes");
    for (const char c : s.timezone) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '/' || c == '+' || c == '-';
        if (!ok)
            return std::unexpected("timezone has an invalid character");
    }
    for (const auto& [name, on] : s.plugins) {
        (void)on;
        if (!is_collection_plugin(name))
            return std::unexpected("unknown plugin key: " + name);
    }
    for (const auto p : kCollectionPlugins) {
        if (!s.plugins.contains(std::string{p}))
            return std::unexpected("plugin key missing: " + std::string{p});
    }
    if (!s.plugins.at(std::string{kRegisteredAppsPlugin}))
        return std::unexpected("registered apps collection cannot be turned off");
    if (s.priority < 0 || s.priority > kMaxPriority)
        return std::unexpected("priority must be between 0 and 1000");
    if (is_root && s.priority != 0)
        return std::unexpected("the root document is the fleet default layer and takes no priority");
    return {};
}

namespace detail {

inline std::string canonical_fields(const EffectiveSettings& e, std::optional<int> priority,
                                    char sep) {
    std::string out = "v1";
    out += sep;
    out += "interval=" + std::to_string(e.interval_s);
    out += sep;
    out += e.window ? "window=" + std::to_string(e.window->start_min) + "-" +
                          std::to_string(e.window->end_min)
                    : std::string{"window=none"};
    out += sep;
    out += "tz=" + e.timezone;
    out += sep;
    for (const auto& [name, on] : e.plugins) {
        out += "plugin." + name + "=" + (on ? "1" : "0");
        out += sep;
    }
    if (priority) {
        out += "priority=" + std::to_string(*priority);
        out += sep;
    }
    return out;
}

} // namespace detail

/// Fixed-order text of a stored document. The hashes always use '\n'; the audit detail renders
/// with ';' so it stays on one line.
[[nodiscard]] inline std::string canonical_text(const CollectionSettings& s, bool with_priority,
                                                char sep = '\n') {
    return detail::canonical_fields(s.effective(),
                                    with_priority ? std::optional<int>{s.priority} : std::nullopt,
                                    sep);
}

[[nodiscard]] inline std::string canonical_text(const EffectiveSettings& e, char sep = '\n') {
    return detail::canonical_fields(e, std::nullopt, sep);
}

/// nullopt = the digest provider failed (sha256_hex.hpp contract); callers answer 503.
[[nodiscard]] inline std::optional<std::string> document_version(const CollectionSettings& s) {
    return sha256_hex(canonical_text(s, /*with_priority=*/true));
}

[[nodiscard]] inline std::optional<std::string> effective_version(const EffectiveSettings& e) {
    return sha256_hex(canonical_text(e));
}

/// Hop cap shared with ManagementGroupStore::get_ancestor_ids.
inline constexpr int kMaxHops = 10;

/// Pick the settings that apply to a device. `member_group_ids` are the groups the device belongs
/// to; `tree` is every group; `docs` every stored document; `killed` maps plugin -> kill-switched.
/// Documents for groups absent from `tree` (a deleted group's orphan) are ignored. Deterministic.
[[nodiscard]] inline std::expected<ResolveResult, std::string>
resolve(const std::vector<std::string>& member_group_ids, const std::vector<GroupNode>& tree,
        const std::vector<StoredDocument>& docs, const std::map<std::string, bool>& killed) {
    std::map<std::string, const GroupNode*> nodes;
    for (const auto& n : tree)
        nodes.emplace(n.id, &n);
    std::map<std::string, const StoredDocument*> by_group;
    for (const auto& d : docs)
        by_group.emplace(d.group_id, &d);

    const auto parent_of = [&](const std::string& id) -> const GroupNode* {
        const auto it = nodes.find(id);
        if (it == nodes.end() || it->second->parent_id.empty())
            return nullptr;
        const auto p = nodes.find(it->second->parent_id);
        return p == nodes.end() ? nullptr : p->second;
    };
    const auto depth_of = [&](const std::string& id) {
        int depth = 0;
        const GroupNode* cur = nodes.at(id);
        while (depth < kMaxHops) {
            cur = parent_of(cur->id);
            if (cur == nullptr)
                break;
            ++depth;
        }
        return depth;
    };

    struct Candidate {
        const StoredDocument* doc;
        const GroupNode* group;
        int depth;
    };
    std::map<std::string, Candidate> candidates; // keyed by group id: one entry per document
    for (const auto& member : member_group_ids) {
        if (member == kRootGroupId || !nodes.contains(member))
            continue;
        const GroupNode* cur = nodes.at(member);
        for (int hops = 0; cur != nullptr && cur->id != kRootGroupId && hops <= kMaxHops; ++hops) {
            if (const auto d = by_group.find(cur->id); d != by_group.end()) {
                candidates.emplace(cur->id, Candidate{d->second, cur, depth_of(cur->id)});
                break;
            }
            cur = parent_of(cur->id);
        }
    }

    // Drop a candidate whose group is an ancestor of another candidate's group.
    std::set<std::string> pruned;
    for (const auto& [id, c] : candidates) {
        const GroupNode* cur = parent_of(id);
        for (int hops = 0; cur != nullptr && hops < kMaxHops; ++hops) {
            if (cur->id != id && candidates.contains(cur->id))
                pruned.insert(cur->id);
            cur = parent_of(cur->id);
        }
    }

    const Candidate* best = nullptr;
    for (const auto& [id, c] : candidates) {
        if (pruned.contains(id))
            continue;
        if (best == nullptr) {
            best = &c;
            continue;
        }
        // priority desc, depth desc, created_at asc, id asc
        const auto key = [](const Candidate& x) {
            return std::make_tuple(-x.doc->settings.priority, -x.depth, x.group->created_at,
                                   x.group->id);
        };
        if (key(c) < key(*best))
            best = &c;
    }

    const CollectionSettings* chosen = &kFleetDefault;
    std::string source;
    if (best != nullptr) {
        chosen = &best->doc->settings;
        source = best->group->id;
    } else if (const auto r = by_group.find(std::string{kRootGroupId}); r != by_group.end()) {
        chosen = &r->second->settings;
        source = std::string{kRootGroupId};
    }

    ResolveResult out;
    out.effective = chosen->effective();
    out.source_group_id = std::move(source);
    // Overlay. A key absent from the document reads as on; the registered apps collector is on
    // unless kill-switched.
    std::map<std::string, bool> plugins;
    for (const auto p : kCollectionPlugins) {
        const std::string name{p};
        const auto k = killed.find(name);
        const bool is_killed = k != killed.end() && k->second;
        bool on = true;
        if (p != kRegisteredAppsPlugin) {
            const auto it = chosen->plugins.find(name);
            on = it == chosen->plugins.end() || it->second;
        }
        plugins.emplace(name, on && !is_killed);
    }
    out.effective.plugins = std::move(plugins);
    auto version = effective_version(out.effective);
    if (!version)
        return std::unexpected("digest provider failed");
    out.version = std::move(*version);
    return out;
}

} // namespace yuzu::server::collection_settings
