#pragma once

/**
 * fleet_topology_store.hpp -- Aggregator + cache for /viz/fleet topology
 *
 * The store turns a vector of per-agent fleet_snapshot.v1 payloads into a
 * single TopologySnapshot, applying:
 *   * Process categorisation (process_category.hpp)
 *   * Cross-machine IP resolution (ip → agent_id map)
 *   * Connection scope classification (Local / InternalFleet / External)
 *   * Optional vulnerability overlay (NvdDatabase::match_inventory)
 *
 * Caching: 60-second TTL keyed by `include_vuln` (LRU-of-2). When a get()
 * call finds the slot cold or expired, exactly one caller refills it; the
 * others wait on the same shared_ptr. Cache and dispatch are decoupled
 * via the `Fetcher` seam -- PR 2 ships this with fake fetchers used by
 * tests; PR 3 will inject the real fetcher that drives the agent dispatch
 * via AgentRegistry::send_to + an agent_service_impl response callback.
 *
 * Thread-safe: a std::shared_mutex guards the slots map; refill runs
 * outside the lock so dispatch latency doesn't block other slot reads.
 *
 * Lifetime: one instance per Server, owned by the daemon for its lifetime.
 * Constructor is called once in server.cpp with the real fetcher injected;
 * never per-request.
 */

#include "fleet_topology_types.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace yuzu::server {

class NvdDatabase; ///< Forward-declare; vuln overlay only uses match_inventory.
class AuditStore;  ///< Forward-declare; push audit (CC6.1/CC7.3 evidence).
struct OfflineEndpoint; ///< Forward-declare (offline_endpoint_store.hpp); see
                        ///< merge_offline_topology() below.

class FleetTopologyStore {
public:
    /// Fetcher seam: produces one RawAgentSnapshot per known fleet agent
    /// within the supplied deadline. Implementations time out individual
    /// agents, set stale=true on no-response rows, and return whatever
    /// they collected. PR 2 uses fakes; PR 3 wires the real dispatch.
    using Fetcher =
        std::function<std::vector<RawAgentSnapshot>(std::chrono::milliseconds deadline)>;

    /// PR 6 / OBS-2: optional observer fired exactly once per refill, with
    /// the wall-clock duration of the fetcher_() call only (not the cache
    /// lock, not the build_snapshot pass). Server wires this to a
    /// Prometheus histogram so operators can distinguish "agent dispatch
    /// is slow" from "the rest of the request is slow" -- the existing
    /// `yuzu_viz_topology_request_seconds` histogram measures the whole
    /// HTTP path. Null-by-default; observer is invoked on success AND on
    /// fetcher exception (so a hung fetcher still produces an upper-bound
    /// observation).
    using FetchDurationObserver = std::function<void(std::chrono::duration<double>)>;

    /// One fleet-roster entry — a registered agent and the session-sourced
    /// identity fields needed to render a stale placeholder cube for it.
    struct RosterEntry {
        std::string agent_id;
        std::string hostname;
        std::string os;
    };

    /// Roster seam (Gate 7 UP-9 / hp-S1): supplies the full set of currently
    /// registered agents. When the push path is taken (pushed_ non-empty),
    /// get() consults this to emit a `stale=true` placeholder for every
    /// registered agent that has NOT pushed a snapshot — so legacy agents
    /// (no fleet_snapshot_json, e.g. mid rolling-upgrade) render as dimmed
    /// cubes instead of vanishing from the topology entirely. Null-by-default
    /// (tests and the dispatch-fetcher-only path don't need it); the dispatch
    /// fetcher already emits its own stale rows for non-responders.
    using RosterProvider = std::function<std::vector<RosterEntry>()>;

    /// @param fetcher        Required. Called on cache miss / expiry.
    /// @param nvd            Optional. When include_vuln=true and nvd is
    ///                       non-null, processes get worst_severity + cve_count.
    ///                       NOTE: PR 2 ships the join wired but inert: the
    ///                       agent's fleet_snapshot.v1 payload does not yet
    ///                       carry installed versions, so match_inventory --
    ///                       which requires a non-empty version per item --
    ///                       returns no matches today. PR 10 (vulnerability
    ///                       overlay) will either extend the agent payload
    ///                       with versions or add a name-only path to NVD.
    /// @param ttl            Cache TTL; defaults to 60 s.
    /// @param fetch_deadline How long the fetcher gets before partial results
    ///                       are accepted; defaults to 5 s. Waiters on a
    ///                       single-flight refill use ttl_+slack as their
    ///                       cv.wait_for bound so a hung fetcher cannot block
    ///                       caller threads forever (UP-8 / CAP-2).
    /// @param max_snapshot_bytes Soft cap on the serialised snapshot size.
    ///                       Refills exceeding this log a WARN and are NOT
    ///                       cached (next get() retries) so a runaway fleet
    ///                       cannot wedge the cache slot at multi-GB.
    ///                       Defaults to 256 MB. Set 0 to disable.
    FleetTopologyStore(Fetcher fetcher, NvdDatabase* nvd = nullptr,
                       std::chrono::milliseconds ttl = std::chrono::seconds(60),
                       std::chrono::milliseconds fetch_deadline = std::chrono::milliseconds(5000),
                       std::size_t max_snapshot_bytes = 256ull * 1024 * 1024);

    FleetTopologyStore(const FleetTopologyStore&) = delete;
    FleetTopologyStore& operator=(const FleetTopologyStore&) = delete;

    /// Returns a snapshot. Either a cache hit (fast path) or a refill
    /// (calls the fetcher synchronously, with `fetch_deadline` budget).
    /// `include_vuln=true` performs the NVD join when nvd_ is set; it is
    /// a no-op when nvd_ is null (worst_severity stays empty).
    std::shared_ptr<const TopologySnapshot> get(bool include_vuln);

    /// Forcibly drop the cache; the next get() will refill. Used by tests
    /// and by the operator-facing `?fresh=1` query parameter.
    void invalidate();

    /// PR 10 hardening — Hard caps on per-snapshot row counts. Apply at
    /// the JSON parser, BEFORE std::vector::reserve(), so a malicious
    /// `[{}, {}, ...]` cannot trigger a ~200 MB allocation per heartbeat
    /// (sec-H1 / UP-8). The cap matches `kFleetSnapshotMaxRows` in the
    /// agent-side `tar_fleet_snapshot.hpp`; agents already truncate at
    /// 4096 per list, so a legitimate snapshot will never trip this.
    /// A snapshot exceeding the cap is rejected wholesale rather than
    /// truncated server-side — the truncation signal belongs to the
    /// producing agent.
    static constexpr std::size_t kPushedSnapshotMaxRows = 4096;
    /// Maximum accepted byte length of a single `fleet_snapshot_json`
    /// HeartbeatRequest payload. The proto comment says "5–20 KB
    /// typically"; the 4096-row cap at this constant's intended max-row
    /// size implies an effective ceiling around 1.3 MB. Reject before
    /// `nlohmann::json::parse` so a JSON-bomb payload (UP-8) cannot
    /// consume parser CPU.
    static constexpr std::size_t kPushedSnapshotMaxBytes = 2ull * 1024 * 1024;

    /// PR 10 hardening — Push-staleness threshold. A pushed snapshot
    /// whose `ts` (epoch seconds the agent emitted it) is older than
    /// wall-clock now minus this constant is rendered as `stale=true`.
    /// Bounded above by 3× the agent's pump interval (30 s) plus
    /// gateway-batch latency, so a legitimately fresh push never trips
    /// it but a stuck pump (UP-3) becomes visible to operators within
    /// ~90 s.
    static constexpr std::chrono::seconds kPushedStaleAfter{90};

    /// PR 10 hardening (Gate 7 UP-3) — IP-claim reclaim window. The UP-1
    /// IP-spoof guard is first-claim-wins, but a claim must not be
    /// *permanent*: an agent that crashes without a clean deregister
    /// (no evict_pushed) would otherwise strand its local_ips forever,
    /// so a re-imaged host re-enrolling on the same DHCP lease is rejected
    /// indefinitely. A claim whose owning agent has not pushed within this
    /// window is treated as abandoned and may be reclaimed by another
    /// agent. Keyed on `server_received_at` (server wall-clock), never the
    /// agent-controlled `ts`, so a stuck-clock agent cannot hold a claim
    /// past its liveness.
    static constexpr std::chrono::seconds kIpClaimReclaimAfter{300};

    /// Parse a fleet_snapshot.v1 JSON document into a RawAgentSnapshot,
    /// enforcing the row + byte caps above and the trust boundary that
    /// `agent_id` and `os` come from the session, never the JSON.
    /// Returns an empty optional on parse failure (caller emits the
    /// metric + audit event). `ex_message` receives the first 256 chars
    /// of the parser's exception text, control-chars stripped, suitable
    /// for inclusion in audit events — log lines should never echo it
    /// directly (sec-M3 / UP-14).
    ///
    /// Shared by every ingestion site (Heartbeat, BatchHeartbeat, and
    /// the legacy dispatch fetcher) so the field set, default values,
    /// exception scope, and row caps stay in lock-step (arch-B3 /
    /// cons-S1). Free function, not a member, because it has no
    /// dependency on store state.
    static std::optional<RawAgentSnapshot> parse_fleet_snapshot_json(std::string_view json,
                                                                     std::string agent_id,
                                                                     std::string os,
                                                                     std::string* ex_message);

    /// PR 10 / UAT 2026-05-12 — Push-based ingestion.
    ///
    /// Agents publish their latest fleet_snapshot.v1 over the heartbeat
    /// channel (HeartbeatRequest.fleet_snapshot_json). Server-side
    /// AgentServiceImpl::Heartbeat parses the JSON into a RawAgentSnapshot
    /// and calls this method. The store keeps the latest snapshot per
    /// agent in `pushed_` and invalidates the cache so the next get()
    /// reads from the pushed map instead of dispatching tar.fleet_snapshot.
    /// Thread-safe: takes `pushed_mu_` plus `slots_mu_` for the
    /// invalidation half. Safe to call from any heartbeat-dispatcher
    /// thread.
    void push_snapshot(RawAgentSnapshot raw);

    /// PR 10 hardening — evict a deregistered agent's pushed slot
    /// (sec-M4 / UP-5). Called from AgentServiceImpl when an agent's
    /// session ends, so a vanished agent stops rendering as a ghost
    /// cube and frees its local_ips for re-use by a re-enrolling host.
    /// Idempotent; no-op when the agent has no pushed slot.
    void evict_pushed(const std::string& agent_id);

    /// CAP-1 (#1002): set a soft cap on the `pushed_` map size. When the
    /// map is at the cap and a NEW agent_id pushes (i.e. would grow the
    /// map), the entry with the smallest `ts` is evicted first.
    /// `cap` is clamped to `kPushedMapHardCap` (100000) to match the
    /// /viz machines_max DoS ceiling. cap=0 disables the cap (legacy
    /// behaviour). Setter is single-init at bring-up, not thread-safe vs
    /// concurrent pushes.
    static constexpr std::size_t kPushedMapHardCap = 100000;
    void set_pushed_map_cap(std::size_t cap) { pushed_map_cap_ = std::min(cap, kPushedMapHardCap); }

    /// Observability for CAP-1 — number of pushes that triggered an LRU
    /// eviction because the map was at cap.
    uint64_t pushed_evicted_for_cap() const noexcept {
        return pushed_evicted_for_cap_.load(std::memory_order_relaxed);
    }

    /// Observability for the UP-1 IP-spoof guard — number of pushes rejected
    /// because their claimed local_ips overlapped a live agent's claim.
    /// A non-zero rate signals either a spoofing campaign or a NAT/DHCP
    /// misconfiguration; either way the operator needs to see it (Gate 7
    /// sre OBS-1 — this counter was previously dark).
    uint64_t pushed_rejected_count() const noexcept {
        return pushed_rejected_count_.load(std::memory_order_relaxed);
    }

    /// Current occupancy of the `pushed_` map. Primary memory-pressure
    /// signal — an operator can alert before `kPushedMapHardCap` (and the
    /// CAP-1 evictions it triggers) is reached (Gate 7 sre OBS-3).
    /// Thread-safe: takes `pushed_mu_`.
    std::size_t pushed_map_size() const {
        std::lock_guard plk(pushed_mu_);
        return pushed_.size();
    }

    /// Round-3 Hardware-merge accessor (item 10, IP column): a copy of the
    /// full agent_id -> claimed-local-ips index, taken under pushed_mu_. Only
    /// currently-connected agents that have pushed at least one
    /// fleet_snapshot (TAR fleet source, 60 s cache) ever appear here — this
    /// is NOT a durable device-CI field, so an offline or TAR-disabled agent
    /// is simply absent (caller renders "—"). O(fleet) copy; call once per
    /// list render, never per row.
    std::unordered_map<std::string, std::vector<std::string>> claimed_ips() const {
        std::lock_guard plk(pushed_mu_);
        return agent_ips_;
    }

    /// Same data as claimed_ips(), narrowed to one agent (the Hardware CI
    /// record's identity lookup) — avoids copying the whole fleet map for a
    /// single-device open. Empty when the agent has never pushed / isn't
    /// currently claimed.
    std::vector<std::string> ips_for(const std::string& agent_id) const {
        std::lock_guard plk(pushed_mu_);
        auto it = agent_ips_.find(agent_id);
        return it == agent_ips_.end() ? std::vector<std::string>{} : it->second;
    }

    /// Set the optional fetcher-duration observer (see
    /// FetchDurationObserver above). Pass an empty function to clear.
    ///
    /// Thread-safe: setter and `get()` synchronise on slots_mu_; `get()`
    /// snapshots the std::function under the lock and invokes it after
    /// dropping the lock. A re-wire applies to refills started after the
    /// setter returns -- in-flight refills run their already-snapshotted
    /// observer to completion. Re-wires are not torn-read-prone.
    /// **Convention** (not enforced): callers wire this once during
    /// server bring-up before the store sees real traffic; mid-traffic
    /// re-wires work but accumulate split-bucket histogram observations
    /// across the boundary, which is rarely useful operationally. (gov
    /// R6 architect SHOULD-1.)
    void set_fetch_duration_observer(FetchDurationObserver observer);

    /// Wire the roster provider (see RosterProvider above). Pass an empty
    /// function to clear. Single-init at bring-up, not thread-safe vs get().
    void set_roster_provider(RosterProvider provider) { roster_provider_ = std::move(provider); }

    /// PR 10 hardening — wire the audit store for push-traceability
    /// (F-1 / CC6.1 / CC7.3). When set, `push_snapshot` emits:
    ///   • One `topology.push.first` AuditEvent the first time a given
    ///     agent_id pushes per-process-lifetime (proves contribution
    ///     without per-heartbeat audit volume — at 100k agents × 30 s
    ///     cadence, per-push audit would blow the audit DB).
    ///   • One `topology.push.rejected` AuditEvent on every rejection
    ///     (parse failure or IP-spoof guard) — rejections are rare so
    ///     the noise floor is acceptable.
    /// nullptr disables audit emission. Setter is single-init at
    /// bring-up, not thread-safe vs. concurrent pushes.
    void set_audit_store(AuditStore* store) { audit_store_ = store; }

    // ── Observability counters ─────────────────────────────────────────────
    uint64_t cache_hits() const noexcept { return cache_hits_.load(std::memory_order_relaxed); }
    uint64_t cache_misses() const noexcept { return cache_misses_.load(std::memory_order_relaxed); }
    /// Number of fetch waiters that piggybacked on an in-flight refill
    /// (single-flight wins). Useful for spotting stampede risk on /viz/fleet.
    uint64_t refill_waiters() const noexcept {
        return refill_waiters_.load(std::memory_order_relaxed);
    }
    /// Refills whose serialised size exceeded max_snapshot_bytes_ and were
    /// therefore NOT cached. A runaway counter signals a misbehaving agent
    /// (or the fleet outgrew the configured cap).
    uint64_t refill_oversize_drops() const noexcept {
        return refill_oversize_drops_.load(std::memory_order_relaxed);
    }
    /// Single-flight waiters that timed out on cv.wait_for before the refill
    /// completed. Non-zero indicates the fetcher is exceeding its deadline.
    uint64_t refill_wait_timeouts() const noexcept {
        return refill_wait_timeouts_.load(std::memory_order_relaxed);
    }
    /// PR 8 forensic counter (gov R8): EdgeScope::Local edges whose reciprocal
    /// half was missing from the agent snapshot and were therefore dropped
    /// before serialisation. Expected to be non-zero under normal churn (kernel
    /// race during teardown, TIME_WAIT halves, agent's 4096-connection cap
    /// cutting a partner). A spike vs steady-state baseline signals systematic
    /// loss -- e.g. an agent reporting half-open sockets, or a kernel-version
    /// change altering /proc/net/tcp atomicity. Surfaces in metrics as
    /// `yuzu_viz_local_edges_dropped_total`.
    uint64_t local_edges_dropped() const noexcept {
        return local_edges_dropped_.load(std::memory_order_relaxed);
    }

    /// Build a TopologySnapshot from raw inputs without any caching. Public
    /// so PR 3 can reuse the same logic in any future on-demand path that
    /// bypasses the cache (e.g. a per-machine drill-in endpoint).
    TopologySnapshot build_snapshot(std::vector<RawAgentSnapshot> raw, bool include_vuln) const;

    /// Sentinel snapshot returned when the fetcher fails on a cold slot --
    /// has generated_at set but machines empty. Public so PR 3 can render
    /// "no fleet data" identically whether the failure was first-call or
    /// later. (governance round 1, UP-9.)
    TopologySnapshot empty_snapshot(bool include_vuln) const;

private:
    Fetcher fetcher_;
    FetchDurationObserver fetch_observer_;
    RosterProvider roster_provider_;
    NvdDatabase* nvd_{nullptr};
    std::chrono::milliseconds ttl_;
    std::chrono::milliseconds fetch_deadline_;
    std::size_t max_snapshot_bytes_;

    struct Slot {
        std::shared_ptr<const TopologySnapshot> snap;
        std::chrono::steady_clock::time_point cached_at{};
        bool refilling{false};
        std::condition_variable cv;
    };

    mutable std::mutex slots_mu_;
    /// Only two slots ever -- false (no vuln) and true (with vuln). A map
    /// keyed by bool is overkill but mirrors the symmetry plainly.
    std::unordered_map<bool, std::unique_ptr<Slot>> slots_;

    /// PR 10: per-agent latest pushed snapshot. Written by push_snapshot()
    /// from the heartbeat dispatcher; read by get() when building the
    /// aggregate. Distinct mutex from slots_mu_ so a high-volume heartbeat
    /// stream from a large fleet does not block /viz/fleet/topology
    /// readers.
    ///
    /// PR 10 hardening — entries are `shared_ptr<const RawAgentSnapshot>`
    /// so the get() refill builds its working vector by copying
    /// pointers, not the underlying 5–20 KB struct each. At 100k-agent
    /// scale the copy cost drops from ~1 GB → ~1 MB and pushed_mu_ is
    /// released after a quick O(N) pointer walk instead of an O(N×K)
    /// deep copy (UP-15 / perf-S3).
    mutable std::mutex pushed_mu_;
    std::unordered_map<std::string, std::shared_ptr<const RawAgentSnapshot>> pushed_;
    /// Reverse index from local_ip → agent_id, maintained alongside the
    /// pushed_ map. Used by push_snapshot to reject local_ips that
    /// another agent has already claimed (UP-1 spoofing defence).
    /// Same lock as pushed_.
    std::unordered_map<std::string, std::string> ip_owner_;
    /// Forward index from agent_id → its claimed local_ips (Gate 7 UP-15 /
    /// perf-B2). Lets push_snapshot / evict_pushed retract an agent's
    /// ip_owner_ entries in O(agent's IPs) instead of an O(whole-map) scan
    /// on every push — at 100k agents × 30 s cadence the old full-map walk
    /// under pushed_mu_ was the lock-convoy hot spot. Same lock as pushed_;
    /// kept strictly in sync with ip_owner_.
    std::unordered_map<std::string, std::vector<std::string>> agent_ips_;
    std::atomic<uint64_t> pushed_count_{0};           // total pushes accepted
    std::atomic<uint64_t> pushed_rejected_count_{0};  // ip-spoof rejections
    std::atomic<uint64_t> pushed_evicted_for_cap_{0}; // CAP-1 (#1002) LRU evictions
    std::size_t pushed_map_cap_{0};                   // 0 = uncapped (legacy)
    /// Agent IDs already audited via `topology.push.first` — emit once
    /// per process lifetime per agent to bound audit volume. Guarded
    /// by pushed_mu_ (already taken when push_snapshot mutates the
    /// map; the audit event itself is emitted outside the lock).
    std::unordered_set<std::string> audited_first_push_;
    AuditStore* audit_store_{nullptr};

    std::atomic<uint64_t> cache_hits_{0};
    std::atomic<uint64_t> cache_misses_{0};
    std::atomic<uint64_t> refill_waiters_{0};
    std::atomic<uint64_t> refill_oversize_drops_{0};
    std::atomic<uint64_t> refill_wait_timeouts_{0};
    /// `mutable` because `build_snapshot()` is const (pure transformation
    /// over `raw`) but updates this observability counter on each drop pass.
    mutable std::atomic<uint64_t> local_edges_dropped_{0};

    bool fresh_locked(const Slot& s) const;

    /// Retract every ip_owner_ entry owned by `agent_id` and drop its
    /// agent_ips_ row. O(agent's IPs), not O(whole map) (Gate 7 UP-15).
    /// MUST be called with pushed_mu_ held.
    void retract_ip_claims_locked(const std::string& agent_id);
};

/// Merge persisted-but-currently-offline endpoints into a live topology
/// snapshot as `stale=true` placeholder `MachineNode`s (#1320 PR 3). Pure
/// transform (no I/O, no locking) shared by `VizRoutes::handle_topology`
/// (REST `GET /api/v1/viz/fleet/topology`) and the MCP `get_fleet_topology`
/// tool so the merge rule -- copy-on-write, online-set dedup, empty stale
/// placeholders -- cannot drift between the two surfaces
/// (docs/api-twin-recipe.md Rule 1; docs/fleet-viz-invariants.md "Durable
/// offline-host invariants").
///
/// Any `persisted` entry whose `agent_id` is already present in
/// `snap->machines` is skipped (currently online -- already in the live
/// snapshot). Every other entry becomes a stale placeholder carrying only
/// `agent_id`/`hostname`/`os` (empty processes/connections/listeners,
/// `ts=0`). Returns `snap` UNCHANGED (the same `shared_ptr`, no copy) when
/// there is nothing to add -- the common all-online steady state pays no
/// copy, matching the caller's own copy-on-write contract.
std::shared_ptr<const TopologySnapshot>
merge_offline_topology(std::shared_ptr<const TopologySnapshot> snap,
                       const std::vector<OfflineEndpoint>& persisted);

} // namespace yuzu::server
