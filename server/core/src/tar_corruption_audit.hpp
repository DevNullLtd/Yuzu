#pragma once

/**
 * tar.db corruption audit gate (#1567).
 *
 * Agents report `yuzu.plugin.tar.db_corruption_total` / `db_quarantine_last`
 * heartbeat tags. AgentHealthStore SURFACES a candidate on every heartbeat whose tags
 * parse (valid tag pair); the gate provides the dedup: ONE map entry per agent
 * (agent_id -> last known quarantine identity + time of the last row this
 * process wrote), bounded by kMaxAgents (one arbitrary entry is evicted at the
 * cap, never a wholesale clear), and, on a miss, ONE lookup of the newest
 * `tar.db.corruption_quarantined` audit row for the agent. Net effect: exactly
 * one audit row per (agent, quarantine identity) across store prunes, server
 * restarts and HA node switches (per server process: another HA node ingesting
 * the same agent can add a second row for the same identity), and a failed or
 * skipped write is retried after the degraded window (the pair is only marked
 * once the row is durable).
 *
 * The identity is agent-asserted and only shape-validated, so the gate also
 * bounds a rotating identity: at most one row per agent per
 * kTarCorruptionAuditMinRowInterval seconds PER SERVER PROCESS (in-memory; a
 * restart or another HA node opens a fresh window). Intermediate quarantines
 * inside one window collapse to the newest identity, which persists in the
 * agent's `last` tag and logs on the first heartbeat after the window. A
 * degraded audit store is probed at most once per
 * kTarCorruptionAuditDegradedRetry seconds gate-wide.
 *
 * Reservation contract: a true from should_log() reserves the gate's single
 * in-flight slot; the caller completes it with exactly one of mark_logged()
 * (row durable) or mark_failed() (write failed). While the slot is held every
 * other should_log() returns false (retried on a later heartbeat), so at most
 * one audit-store call is in flight gate-wide.
 *
 * The lookup and the write are synchronous audit-store calls on the heartbeat
 * ingest thread, outside AgentHealthStore's mutex. Once the row is durable the
 * map answers with a hash lookup. If candidates ever become frequent this must
 * move to a queue.
 *
 * Pure: the audit-store query and the clock are injected.
 */

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yuzu::server::detail {

/// Heartbeat tags produced by the agent's plugin bridge for the tar plugin's
/// `heartbeat.db_corruption_total` / `heartbeat.db_quarantine_last` KV keys.
inline constexpr const char* kTarTagCorruptionTotal = "yuzu.plugin.tar.db_corruption_total";
inline constexpr const char* kTarTagQuarantineLast = "yuzu.plugin.tar.db_quarantine_last";

/// Audit-row verb and target type for a tar.db quarantine (documented in
/// docs/user-manual/audit-log.md). Shared by the dedup query and the emit.
inline constexpr const char* kTarCorruptionAuditAction = "tar.db.corruption_quarantined";
inline constexpr const char* kTarCorruptionAuditTargetType = "Agent";

/// Minimum seconds between two rows for one agent (bounds a rotating,
/// agent-asserted identity to 144 rows/day/agent).
inline constexpr int64_t kTarCorruptionAuditMinRowInterval = 600;
/// While the audit store answers "degraded", skip lookups for this long.
inline constexpr int64_t kTarCorruptionAuditDegradedRetry = 60;

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
    using NowFn = std::function<int64_t()>;

    explicit TarCorruptionAuditGate(LatestFn latest, NowFn now_s = &steady_seconds)
        : latest_(std::move(latest)), now_s_(std::move(now_s)) {}

    /// True iff a new audit row should be written for (agent, quarantine).
    /// A true return holds the in-flight slot: complete it with mark_logged or mark_failed.
    [[nodiscard]] bool should_log(const std::string& agent_id, const std::string& quarantine) {
        const auto now = now_s_();
        {
            std::lock_guard lock(mu_);
            if (now < degraded_until_)
                return false; // degraded store: no lookup until the window ends
            if (in_flight_)
                return false; // one store call in flight gate-wide; retried next heartbeat
            if (const auto it = agents_.find(agent_id); it != agents_.end()) {
                if (it->second.identity == quarantine)
                    return false; // already durable
                if (it->second.last_row_at &&
                    now - *it->second.last_row_at < kTarCorruptionAuditMinRowInterval)
                    return false; // rotating identity: rate-limited, retried later
            }
            in_flight_ = true;
        }
        std::optional<std::optional<std::string>> latest;
        try {
            latest = latest_(agent_id); // outside mu_: a store round-trip
        } catch (...) {
            std::lock_guard lock(mu_); // never strand the slot on a throwing lookup
            in_flight_ = false;
            throw;
        }
        std::lock_guard lock(mu_);
        if (!latest) {
            in_flight_ = false;
            degraded_until_ = now + kTarCorruptionAuditDegradedRetry;
            return false; // no write, not marked -> retried after the window
        }
        if (*latest && **latest == quarantine) {
            in_flight_ = false;
            remember_locked(agent_id, quarantine, std::nullopt); // durable (prior run / other node)
            return false;
        }
        return true; // slot stays held for the caller's write
    }

    void mark_logged(const std::string& agent_id, const std::string& quarantine) {
        std::lock_guard lock(mu_);
        in_flight_ = false;
        remember_locked(agent_id, quarantine, now_s_());
    }

    /// The caller's audit write failed: release the slot and open the degraded window.
    void mark_failed() {
        std::lock_guard lock(mu_);
        in_flight_ = false;
        degraded_until_ = now_s_() + kTarCorruptionAuditDegradedRetry;
    }

private:
    static constexpr std::size_t kMaxAgents = 65536;
    struct Entry {
        std::string identity;
        std::optional<int64_t> last_row_at; // set only for rows this process wrote
    };
    static int64_t steady_seconds() {
        return std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }
    void remember_locked(const std::string& agent_id, const std::string& quarantine,
                         std::optional<int64_t> row_at) {
        if (agents_.size() >= kMaxAgents && !agents_.contains(agent_id))
            agents_.erase(agents_.begin()); // bounded; the audit-store lookup backs it
        agents_[agent_id] = Entry{quarantine, row_at};
    }
    LatestFn latest_;
    NowFn now_s_;
    std::mutex mu_;
    std::unordered_map<std::string, Entry> agents_;
    int64_t degraded_until_{0};
    bool in_flight_{false}; // a true should_log() awaiting mark_logged / mark_failed
};

} // namespace yuzu::server::detail
