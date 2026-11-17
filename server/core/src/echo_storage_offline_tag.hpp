#pragma once

/**
 * The agent's Echo "storage offline" heartbeat tag, parsed for the fleet gauge
 * `yuzu_fleet_echo_storage_offline{reason}` (and the YuzuEchoStorageOffline alert).
 *
 * When Echo's database cannot be opened (the v10 roll-up migration failed, or lacks the free disk
 * it needs) the agent's echo plugin loads OFFLINE and retries; it publishes the reason as the KV key
 * `heartbeat.storage_offline`, which the plugin heartbeat bridge turns into the status tag below.
 * Without this gauge such an agent drops out of yuzu_fleet_plugin_init_failed (the plugin no longer
 * fails init) with nothing replacing it.
 *
 * The tag value is agent-controlled, so the label set is CLOSED: the three tokens the plugin
 * writes, and `unknown` for anything else (a renamed token, an over-long or newline-bearing value).
 * The tokens are duplicated literals of agents/plugins/echo/src/echo_status_format.hpp's
 * offline_reason_token(): there is no shared header between a plugin and the server, so a test on
 * each side pins the strings, and a rename on one side only would surface as reason=unknown. The
 * agent-side pin is tests/unit/test_echo_open_retry.cpp, case "offline_reason_token: the literals
 * the server's gauge parser mirrors".
 *
 * Pure.
 */

#include <array>
#include <cstddef>
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// The status tag the agent publishes (plugin `echo`, KV key `heartbeat.storage_offline`).
inline constexpr const char* kEchoTagStorageOffline = "yuzu.plugin.echo.storage_offline";

/// The closed gauge label set, in index order; the last entry catches every unrecognised value.
inline constexpr std::array<std::string_view, 4> kEchoStorageOfflineReasons{
    "free_space", "migration_failed", "open_failed", "unknown"};

/// Map a tag value to its label index: nullopt for an empty value (not offline), the token's
/// index for an exact match, the `unknown` index for anything else.
[[nodiscard]] constexpr std::optional<std::size_t>
parse_echo_storage_offline(std::string_view raw) noexcept {
    if (raw.empty())
        return std::nullopt;
    for (std::size_t i = 0; i + 1 < kEchoStorageOfflineReasons.size(); ++i)
        if (raw == kEchoStorageOfflineReasons[i])
            return i;
    return kEchoStorageOfflineReasons.size() - 1;
}

} // namespace yuzu::server::detail
