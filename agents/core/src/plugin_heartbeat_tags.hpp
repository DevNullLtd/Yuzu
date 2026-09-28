#pragma once

/**
 * Plugin -> heartbeat-tag bridge (#1567).
 *
 * A plugin publishes bounded facts into its OWN KV namespace under the
 * `heartbeat.` prefix (the existing yuzu_ctx_storage_set ABI; no ABI change).
 * On every heartbeat the agent turns each loaded plugin's `heartbeat.*` keys
 * into `yuzu.plugin.<plugin>.<key>` status tags. Values are agent-controlled:
 * the caps below bound them here, and the server parses them defensively.
 *
 * Pure: the KV is reached only through the injected list/get callbacks, so it
 * is unit-tested with lambdas (no KvStore, no disk).
 *
 * Bounds a byte-length and a key count, nothing more: a future NUMERIC
 * consumer that sums a tag's raw value into a fleet gauge (rather than only
 * counting agents, as tar_corruption_audit.hpp's parser does today) must add
 * its OWN plausibility ceiling, mirroring the kMaxPlausible*Count pattern in
 * the sibling spark_fleet_tags.hpp/guardian_*_fleet_tags.hpp headers — an
 * unbounded value summed into a double silently annihilates every honest
 * agent's contribution via IEEE-754. A plugin publishing more than
 * kPluginHeartbeatMaxKeys keys has the excess silently dropped (sorted,
 * truncated) with no warning to the plugin author; not reachable today (every
 * current consumer publishes at most 2 keys).
 */

#include <algorithm>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

inline constexpr std::size_t kPluginHeartbeatMaxKeys = 8;
inline constexpr std::size_t kPluginHeartbeatMaxKeyLen = 32;
inline constexpr std::size_t kPluginHeartbeatMaxValueBytes = 64;
inline constexpr std::string_view kPluginHeartbeatPrefix = "heartbeat.";

[[nodiscard]] inline bool plugin_heartbeat_key_ok(std::string_view suffix) noexcept {
    if (suffix.empty() || suffix.size() > kPluginHeartbeatMaxKeyLen)
        return false;
    return std::all_of(suffix.begin(), suffix.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    });
}

/// `list_fn(plugin, prefix)` returns the plugin's full keys with that prefix;
/// `get_fn(plugin, key)` returns the value (nullopt if it vanished).
template <typename TagMap>
void emit_plugin_heartbeat_tags(
    TagMap& tags, const std::vector<std::string>& plugin_names,
    const std::function<std::vector<std::string>(std::string_view, std::string_view)>& list_fn,
    const std::function<std::optional<std::string>(std::string_view, std::string_view)>& get_fn) {
    for (const auto& plugin : plugin_names) {
        auto keys = list_fn(plugin, kPluginHeartbeatPrefix);
        std::sort(keys.begin(), keys.end());
        if (keys.size() > kPluginHeartbeatMaxKeys)
            keys.resize(kPluginHeartbeatMaxKeys);
        for (const auto& key : keys) {
            if (key.size() <= kPluginHeartbeatPrefix.size() ||
                std::string_view{key}.substr(0, kPluginHeartbeatPrefix.size()) !=
                    kPluginHeartbeatPrefix)
                continue;
            const auto suffix = std::string_view{key}.substr(kPluginHeartbeatPrefix.size());
            if (!plugin_heartbeat_key_ok(suffix))
                continue;
            auto value = get_fn(plugin, key);
            if (!value || value->size() > kPluginHeartbeatMaxValueBytes)
                continue;
            tags["yuzu.plugin." + plugin + "." + std::string{suffix}] = std::move(*value);
        }
    }
}

/// `yuzu.plugins_failed=<comma-joined names>` for plugins whose init failed;
/// omitted when none. (A plugin that is not installed never appears here.)
template <typename TagMap>
void emit_plugins_failed_tag(TagMap& tags, const std::vector<std::string>& failed) {
    if (failed.empty())
        return;
    std::string joined;
    for (const auto& n : failed) {
        if (!joined.empty())
            joined += ',';
        joined += n;
    }
    tags["yuzu.plugins_failed"] = std::move(joined);
}

} // namespace yuzu::agent
