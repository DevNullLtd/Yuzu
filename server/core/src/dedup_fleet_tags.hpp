#pragma once

/// @file dedup_fleet_tags.hpp
/// Reader side of the agent command-dedup store's fleet telemetry (#3663, HA WS-0 / WS-11).
///
/// The agent (agents/core/src/agent.cpp, heartbeat block next to `yuzu.dedup_degraded`) carries
/// the durable dedup store's safety-net signals on every heartbeat, because the agent has no
/// /metrics endpoint: that heartbeat is the ONLY channel by which an operator can learn that an
/// endpoint is running its commands undeduplicated (fail-open, ADR-2002 WS-0 invariant 7). This
/// header is the single source of truth, on the server, for those `yuzu.dedup_*` tag keys, the
/// `yuzu_fleet_*` gauge each one rolls up into, its HELP text, and the forged-value-safe parse
/// of the agent-supplied value. AgentHealthStore::recompute_metrics consumes it.
///
/// The keys are duplicated here rather than `#include`d from the agent ON PURPOSE - the same
/// rationale as guardian_health_fleet_tags.hpp: server production code including an agent
/// private header would add an upward server -> agent dependency edge the build graph does not
/// have and must not gain. Two tests bind the sides: tests/test_dedup_fleet_tags_lexical.py pins
/// the keys against the agent source text (every `yuzu.dedup_*` tag agent.cpp emits has a row
/// here or a reasoned exemption, and the reverse), so a rename on either side without the other
/// is a red test, not a silently-dead gauge; and tests/unit/server/test_dedup_fleet_tags.cpp
/// tests the parse and classification below directly.
///
/// SHAPE: a COUNT OF AGENTS, not a sum of counters. Every counter tag is a per-process
/// cumulative value that resets to 0 on an agent restart, so an unlabelled fleet SUM of them
/// has no churn-robust `increase()` alert (docs/observability-conventions.md). Counting the
/// agents whose value is non-zero sidesteps that: a restart that zeroes one agent's counter
/// removes it from the count once its next heartbeat arrives, and the question an operator
/// actually has ("how many endpoints are affected?") is the thing published. Same shape as
/// `yuzu_fleet_ota_signature_refusing_agents`. Consequence, stated in every HELP string below:
/// a counter-derived gauge means "since that agent's last restart", NOT "currently". Only the
/// degraded flag is a live 0/1 reading, which is why it is the only one with an alert.
///
/// POPULATION AND SCOPE: every gauge here is computed over the agents with a heartbeat in the
/// last 90 s (the health store's staleness window; an offline agent, or one that heartbeats
/// slower than 90 s, drops out), and `AgentHealthStore` is per core replica, so each replica
/// exports only the agents attached to it (sum across replicas; a failover can briefly count an
/// agent on two). `yuzu_fleet_agents_dedup_store_degraded` covers a store that failed to OPEN;
/// a store that opened and later failed writes shows only on the latched `..._claim_erroring`,
/// `..._record_erroring` and `..._release_erroring` counts, which have no alert.
///
/// WHAT ABSENCE MEANS: the count gauges are server-owned counts over the reporting population
/// and are published every sweep, 0 included, so a flat 0 is a measurement. Whether anyone is
/// being measured is what `yuzu_fleet_agents_dedup_reporting` says - without it a fleet of
/// agents that predate the tag reads as a clean fleet. The capacity gauge (`..._rows_max`) is
/// the opposite: a MAX of a per-agent reading, cleared and rebuilt each sweep, ABSENT when no
/// agent reported a valid value rather than a fabricated 0.
///
/// ADR-1005 exception ledger, 2026-07-14 class-level entry: a `/metrics`-only fleet gauge
/// family is observability, not capability, so it carries no REST/MCP twin obligation.

#include <cstddef>
#include <iterator> // std::size
#include <optional>
#include <string_view>

namespace yuzu::server::detail {

/// Upper bound on an accepted dedup tag value. Above it - or non-numeric, empty, or longer than
/// 10 characters - the value is REJECTED (counted in the tag_rejected meta-gauge), never clamped:
/// clamping would let a forged tag still move a published number. The honest values are tiny
/// (a ring bound of 20000 rows; counters that grow by one per failed command), so 1e9 is
/// orders of magnitude of headroom, not a tuned threshold.
inline constexpr unsigned long long kMaxPlausibleDedupValue = 1'000'000'000ULL;

/// How a per-agent value becomes a membership in the agent count.
enum class DedupCountKind {
    /// A true 0/1 reading. "1" counts; "0" is a valid not-counted reading; anything else is
    /// REJECTED (a flag that reads 2 is a forged or broken value, not a larger flag).
    kFlag,
    /// A per-process cumulative counter. Any value > 0 counts; "0" is a valid not-counted
    /// reading.
    kPositiveCounter,
};

/// One agent-count signal: the agent's heartbeat tag key, how it is read, the fleet gauge it
/// counts into, and that gauge's Prometheus HELP text.
struct DedupAgentCountMetric {
    const char* tag;
    DedupCountKind kind;
    const char* gauge;
    const char* help;
};

/// The `dedup_degraded` row is first: `kDedupPresenceIndex` names it as the reporting signal.
/// Every agent that carries the dedup block emits it on every heartbeat as a real 0/1 reading
/// (never absent-reads-as-zero), so "this agent sent a valid degraded flag" is exactly "this
/// agent is measured".
inline constexpr std::size_t kDedupPresenceIndex = 0;

/// HELP text is 7-bit ASCII (scripts/ci/check-metrics-help-ascii.sh).
inline constexpr DedupAgentCountMetric kDedupAgentCountMetrics[] = {
    {"yuzu.dedup_degraded", DedupCountKind::kFlag, "yuzu_fleet_agents_dedup_store_degraded",
     "Agents whose durable command-dedup store could not be opened (heartbeat tag "
     "yuzu.dedup_degraded = 1). Such an agent still runs commands but WITHOUT replay "
     "protection: a redelivered command may execute twice (at-least-once, fail-open by design, "
     "ADR-2002 WS-0). Covers a store that failed to OPEN only: a store that opened and later "
     "failed writes shows on yuzu_fleet_agents_dedup_claim_erroring, which has no alert. A "
     "live reading over agents with a heartbeat in the last 90 s, recomputed every sweep and "
     "exported per core replica (sum across replicas): it clears within about 45 s of the "
     "restart (the first heartbeat comes one interval, 30 s by default, after the agent starts, "
     "then up to one 15 s sweep), and an agent offline for more than 90 s leaves it without "
     "having been fixed. >0 sustained is the YuzuDedupStoreDegraded sample alert"},
    {"yuzu.dedup_replays", DedupCountKind::kPositiveCounter, "yuzu_fleet_agents_dedup_replaying",
     "Agents that have served at least one durable terminal-outcome replay since their last "
     "restart (heartbeat tag yuzu.dedup_replays > 0). Informational: a replay is the dedup "
     "store doing its job on a redelivered command, so a non-zero value is normal, not a "
     "fault. Per-process counter, so it means since that agent restarted, not currently. "
     "MONITOR-ONLY"},
    {"yuzu.dedup_claim_errors", DedupCountKind::kPositiveCounter,
     "yuzu_fleet_agents_dedup_claim_erroring",
     "Agents whose dedup store has failed at least one claim since their last restart "
     "(heartbeat tag yuzu.dedup_claim_errors > 0). Each is a command that ran undeduplicated "
     "because the store write failed after boot (disk full, I/O error); unlike "
     "dedup_store_degraded the store DID open. Per-process counter: since that agent "
     "restarted, not currently. MONITOR-ONLY"},
    {"yuzu.dedup_record_terminal_misses", DedupCountKind::kPositiveCounter,
     "yuzu_fleet_agents_dedup_record_terminal_missing",
     "Agents that have recorded at least one terminal outcome matching no in-flight row since "
     "their last restart (heartbeat tag yuzu.dedup_record_terminal_misses > 0): the command ran "
     "undeduplicated, or a duplicate terminal arrived. NOT a measure of the ring-eviction "
     "double-execute, which is not separately detectable. Per-process counter: since that "
     "agent restarted, not currently. MONITOR-ONLY"},
    {"yuzu.dedup_record_errors", DedupCountKind::kPositiveCounter,
     "yuzu_fleet_agents_dedup_record_erroring",
     "Agents whose dedup store has failed to record at least one terminal outcome since their "
     "last restart (heartbeat tag yuzu.dedup_record_errors > 0). A redelivery of that command "
     "answers RUNNING instead of replaying its result. Per-process counter: since that agent "
     "restarted, not currently. MONITOR-ONLY"},
    {"yuzu.dedup_release_errors", DedupCountKind::kPositiveCounter,
     "yuzu_fleet_agents_dedup_release_erroring",
     "Agents whose dedup store has failed at least one claim release since their last restart "
     "(heartbeat tag yuzu.dedup_release_errors > 0): a possibly-leaked claim, which answers "
     "RUNNING to every redelivery of that command and never re-runs it. Per-process counter: "
     "since that agent restarted, not currently. MONITOR-ONLY"},
};

inline constexpr std::size_t kNDedupAgentCountMetrics = std::size(kDedupAgentCountMetrics);
static_assert(kDedupPresenceIndex < kNDedupAgentCountMetrics,
              "the presence row must exist in the table");

/// Capacity signal: the agent's cached row count (in-flight + terminal) in its dedup store.
/// Rolled up as the fleet MAX (a sum of row counts is meaningless; the question is "how close
/// is the fullest store to its bound"), hence the `_max` suffix. ABSENT, not 0, when no agent
/// reported a valid value. Compare against kMaxDedupRows (20000, in agents/core
/// command_dedup_store.hpp; not restated as a constant here, same no-upward-edge rule, and
/// pinned to the HELP text by tests/test_dedup_fleet_tags_lexical.py) plus one prune interval
/// (512).
inline constexpr const char* kDedupRowsTag = "yuzu.dedup_rows";
inline constexpr const char* kDedupRowsMaxGauge = "yuzu_fleet_dedup_rows_max";
inline constexpr const char* kDedupRowsMaxHelp =
    "Largest durable command-dedup store, in rows (in-flight + terminal), reported by any agent "
    "(heartbeat tag yuzu.dedup_rows, an approximate cached count that can over-read after a "
    "burst of released claims). The store is a ring that keeps the newest 20000 terminal rows, "
    "so a healthy value tops out near 20500; in-flight rows from crashed commands are never "
    "evicted and are one way it grows past that. It is a MAX of agent-reported values, per "
    "core replica (take the max across replicas, not the sum): one agent's forged value up to "
    "the plausibility ceiling owns it and it names no agent, so treat it as a hint and "
    "investigate sustained values above about 25000. Absent when no agent reports it";

/// Meta-gauges, the coverage denominators that absence would otherwise hide.
inline constexpr const char* kDedupReportingGauge = "yuzu_fleet_agents_dedup_reporting";
inline constexpr const char* kDedupReportingHelp =
    "Agents with a heartbeat in the last 90 s whose latest heartbeat carried a valid "
    "yuzu.dedup_degraded flag, i.e. the agents the yuzu_fleet_agents_dedup_* counts are "
    "measuring. Exported per core replica (each replica counts only the agents attached to it; "
    "sum across replicas). An agent that predates the tag, or whose flag was rejected, is not "
    "counted here, so a 0 in the dedup counts is only reassuring when this is non-zero and "
    "close to the number of agents you expect; the counts can exceed this when an agent's flag "
    "was rejected but another of its dedup tags was valid";
inline constexpr const char* kDedupTagRejectedGauge = "yuzu_fleet_agents_dedup_tag_rejected";
inline constexpr const char* kDedupTagRejectedHelp =
    "Agents whose latest heartbeat carried at least one yuzu.dedup_* value the server "
    "rejected (non-numeric, empty, over-long, above the plausibility ceiling, or a degraded "
    "flag other than 0 or 1). A rejected value is dropped from the counts, never clamped; "
    ">0 means an agent is sending malformed or forged dedup tags";

/// Forged-value-safe parse of an agent-supplied dedup tag. Digits only, 1 to 10 characters,
/// at most kMaxPlausibleDedupValue; "0" is valid. Anything else is nullopt (rejected). Leading
/// zeros are ACCEPTED ("0000000001" is 1): the agent writes std::to_string and never emits
/// them, the value is only compared and counted, never summed or used as a label, and rejecting
/// them would only add a way for a benign formatting change to drop an agent from the counts.
/// The 10-character cap is load-bearing: it is what keeps `v * 10 + digit` from wrapping an
/// unsigned long long, so a 20-digit forgery can never read as a small number.
/// No allocation, no exceptions: the value is attacker-controlled and read once per agent per
/// sweep under the health-store lock.
[[nodiscard]] inline std::optional<unsigned long long> parse_dedup_value(
    std::string_view raw) noexcept {
    if (raw.empty() || raw.size() > 10)
        return std::nullopt;
    unsigned long long v = 0;
    for (const char c : raw) {
        if (c < '0' || c > '9')
            return std::nullopt;
        v = v * 10ULL + static_cast<unsigned long long>(c - '0');
    }
    if (v > kMaxPlausibleDedupValue)
        return std::nullopt;
    return v;
}

/// Verdict for one agent's value against one row.
enum class DedupVerdict {
    kRejected,   ///< malformed / forged: counted in tag_rejected, contributes to nothing
    kNotCounted, ///< a valid reading that does not put the agent in the count (0)
    kCounted,    ///< a valid reading that puts the agent in the count
};

[[nodiscard]] inline DedupVerdict classify_dedup_value(DedupCountKind kind,
                                                       std::string_view raw) noexcept {
    const auto v = parse_dedup_value(raw);
    if (!v)
        return DedupVerdict::kRejected;
    if (kind == DedupCountKind::kFlag && *v > 1)
        return DedupVerdict::kRejected;
    return *v > 0 ? DedupVerdict::kCounted : DedupVerdict::kNotCounted;
}

} // namespace yuzu::server::detail
