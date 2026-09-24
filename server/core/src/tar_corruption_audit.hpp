#pragma once

/**
 * tar.db corruption audit gate (#1567).
 *
 * Agents report `yuzu.plugin.tar.db_corruption_total` / `db_quarantine_last`
 * heartbeat tags. AgentHealthStore SURFACES a candidate on every heartbeat whose tags
 * parse (valid tag pair); the gate provides the dedup: a bounded in-process
 * seen-set of (agent_id, quarantine_last) and, on a miss, ONE lookup of the
 * newest `tar.db.corruption_quarantined` audit row for the agent. Net effect:
 * exactly one audit row per (agent, quarantine identity) across store prunes,
 * server restarts and HA node switches, and a failed or skipped write is
 * retried on the next heartbeat (the pair is only marked once the row is
 * durable).
 *
 * The lookup and the write are synchronous audit-store calls on the heartbeat
 * ingest thread, outside AgentHealthStore's mutex. Once the row is durable the
 * seen-set answers with a hash lookup; while it is not, that is one lookup per
 * heartbeat for agents with corruption > 0. If candidates ever become frequent
 * this must move to a queue.
 *
 * Pure: the audit-store query is injected.
 */

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>

namespace yuzu::server::detail {

/// Heartbeat tags produced by the agent's plugin bridge for the tar plugin's
/// `heartbeat.db_corruption_total` / `heartbeat.db_quarantine_last` KV keys.
inline constexpr const char* kTarTagCorruptionTotal = "yuzu.plugin.tar.db_corruption_total";
inline constexpr const char* kTarTagQuarantineLast = "yuzu.plugin.tar.db_quarantine_last";

/// Parse `yuzu.plugin.tar.db_corruption_total`: digits only, <= 18 chars, > 0.
[[nodiscard]] inline std::optional<int64_t> parse_tar_corruption_total(std::string_view raw) {
    if (raw.empty() || raw.size() > 18)
        return std::nullopt;
    int64_t v = 0;
    for (char c : raw) {
        if (c < '0' || c > '9')
            return std::nullopt;
        v = v * 10 + (c - '0');
    }
    if (v <= 0)
        return std::nullopt;
    return v;
}

/// `<epoch>:<basename>` as published by the agent: 1-18 digits, one ':', then a
/// 1-60 char basename from [A-Za-z0-9._-] (the real name is
/// tar.db.corrupt-<epoch>[-<n>]); no path separators; total <= 80.
[[nodiscard]] inline bool valid_tar_quarantine_last(std::string_view q) noexcept {
    if (q.empty() || q.size() > 80)
        return false;
    const auto colon = q.find(':');
    if (colon == std::string_view::npos || colon < 1 || colon > 18)
        return false;
    for (std::size_t i = 0; i < colon; ++i)
        if (q[i] < '0' || q[i] > '9')
            return false;
    const auto base = q.substr(colon + 1);
    if (base.empty() || base.size() > 60)
        return false;
    for (char c : base) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                        c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

/// Audit-row detail contract shared by the server sink (encode) and the
/// durable-dedup lookup (decode).
[[nodiscard]] inline std::string encode_tar_corruption_detail(int64_t total,
                                                              std::string_view quarantine) {
    return "corruption_total=" + std::to_string(total) + " quarantine=" + std::string(quarantine);
}

[[nodiscard]] inline std::optional<std::string>
decode_tar_quarantine_from_detail(std::string_view detail) {
    constexpr std::string_view kKey = "quarantine=";
    const auto pos = detail.find(kKey);
    if (pos == std::string_view::npos)
        return std::nullopt;
    return std::string(detail.substr(pos + kKey.size()));
}

class TarCorruptionAuditGate {
public:
    /// Newest logged quarantine identity for the agent. Outer nullopt = the
    /// audit store is degraded/unqueryable; inner nullopt = no prior row.
    using LatestFn =
        std::function<std::optional<std::optional<std::string>>(const std::string& agent_id)>;

    explicit TarCorruptionAuditGate(LatestFn latest) : latest_(std::move(latest)) {}

    /// True iff a new audit row should be written for (agent, quarantine).
    [[nodiscard]] bool should_log(const std::string& agent_id, const std::string& quarantine) {
        const auto key = make_key(agent_id, quarantine);
        {
            std::lock_guard lock(mu_);
            if (seen_.contains(key))
                return false;
        }
        const auto latest = latest_(agent_id); // outside mu_: a store round-trip
        if (!latest)
            return false; // degraded store: no write, not marked -> retried later
        if (*latest && **latest == quarantine) {
            mark_logged(agent_id, quarantine); // already durable (prior run / other node)
            return false;
        }
        return true;
    }

    void mark_logged(const std::string& agent_id, const std::string& quarantine) {
        std::lock_guard lock(mu_);
        if (seen_.size() >= kMaxSeen)
            seen_.clear(); // bounded; the audit-store lookup backs it
        seen_.insert(make_key(agent_id, quarantine));
    }

private:
    static constexpr std::size_t kMaxSeen = 4096;
    static std::string make_key(const std::string& a, const std::string& q) {
        return a + "\n" + q;
    }
    LatestFn latest_;
    std::mutex mu_;
    std::unordered_set<std::string> seen_;
};

} // namespace yuzu::server::detail
