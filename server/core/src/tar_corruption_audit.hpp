#pragma once

/**
 * tar.db corruption audit gate (#1567).
 *
 * Agents report `yuzu.plugin.tar.db_corruption_total` / `db_quarantine_last`
 * heartbeat tags. AgentHealthStore only SURFACES a candidate (valid tag, and no
 * previous snapshot or a changed quarantine identity); its memory is per-process
 * and pruned every ~90 s, so it cannot dedup on its own. This gate provides the
 * DURABLE dedup: a bounded in-process seen-set of (agent_id, quarantine_last)
 * and, on a miss, ONE lookup of the newest `tar.db.corruption_quarantined`
 * audit row for the agent. Net effect: exactly one audit row per (agent,
 * quarantine identity) across store prunes, server restarts and HA node
 * switches.
 *
 * The lookup and the write are synchronous audit-store calls on the heartbeat
 * ingest thread; they run outside AgentHealthStore's mutex and only once per
 * (agent, server process) for agents with corruption > 0. If candidates ever
 * become frequent (e.g. a churning tag) this must move to a queue.
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

/// `<epoch>:<basename>` as published by the agent: non-empty, <= 80 chars.
[[nodiscard]] inline bool valid_tar_quarantine_last(std::string_view q) noexcept {
    return !q.empty() && q.size() <= 80;
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
