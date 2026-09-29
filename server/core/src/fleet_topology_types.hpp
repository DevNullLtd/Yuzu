#pragma once

/**
 * fleet_topology_types.hpp -- Data types + JSON serialization for /viz/fleet
 *
 * Three top-level shapes consumed by the renderer:
 *   MachineNode     -- one fleet host (cube in the 3D scene)
 *   ProcessNode     -- one process inside a MachineNode (interior dot)
 *   ConnectionEdge  -- one open socket from src process; scope tells the
 *                       renderer whether to draw an interior line, an
 *                       inter-cube edge, or an "external/Internet" edge
 *
 * The renderer JSON shape is a concession to bandwidth: short keys, scalar
 * values where possible, optional fields omitted when empty. Test suite
 * locks the wire format.
 *
 * RawAgentSnapshot is the *input* shape -- one parsed fleet_snapshot.v1
 * payload from a single agent. The FleetTopologyStore aggregates a vector
 * of these into a TopologySnapshot.
 */

#include "process_category.hpp"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

/// One process inside a machine cube.
struct ProcessNode {
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string user;
    ProcessCategory category{ProcessCategory::Other};
    /// CVE severity from the worst CVE matched against this process by
    /// name. Empty when no overlay was requested or no match found.
    /// Values: "critical" / "high" / "medium" / "low".
    std::string worst_severity;
    /// Number of CVE matches at any severity. 0 when overlay disabled.
    int cve_count{0};
};

/// Scope of a connection edge -- determines how the renderer draws it.
enum class EdgeScope {
    Local,         ///< local_addr and remote_addr both loopback (interior line)
    InternalFleet, ///< remote_addr resolves to another fleet machine
    External,      ///< remote_addr is outside the fleet (Internet sentinel)
};

inline std::string_view scope_to_string(EdgeScope s) {
    switch (s) {
    case EdgeScope::Local:
        return "local";
    case EdgeScope::InternalFleet:
        return "internal_fleet";
    case EdgeScope::External:
        return "external";
    }
    return "external";
}

/// One TCP / UDP socket originating from a process on this machine.
/// Inbound (LISTEN-only) sockets do not appear; only ESTABLISHED + outbound
/// CLOSE_WAIT / CLOSING / etc. with non-empty remote endpoints.
struct ConnectionEdge {
    std::string proto; ///< "tcp" / "tcp6" / "udp" / "udp6"
    uint32_t src_pid{0};
    std::string src_addr;
    int src_port{0};
    std::string dst_addr;
    int dst_port{0};
    /// agent_id of the destination machine when remote_addr resolves to a
    /// fleet host; empty for Local and External scopes.
    std::string dst_agent_id;
    /// Resolved destination pid on the SAME machine for `EdgeScope::Local`
    /// connections only. Populated by pairing each loopback connection with
    /// its reciprocal half (same 4-tuple, swapped). Zero (the default) when
    /// the destination is unresolved -- PR 8 drops those before they reach
    /// the renderer, so a `dst_pid == 0` on a Local edge that survives into
    /// a TopologySnapshot is a build-snapshot bug.
    uint32_t dst_pid{0};
    EdgeScope scope{EdgeScope::External};
    std::string state; ///< ESTABLISHED, CLOSE_WAIT, etc.
};

/// One LISTEN socket on a fleet machine. PR 9 / UAT 2026-05-12 split
/// these out of the `connections` array so the renderer can draw a
/// per-port socket primitive on the cube top face — operators expect
/// "the ports a machine is listening on" to be a first-class visual,
/// not a derived facet of an active flow array that drops LISTEN-only
/// rows. `pid` and `process_name` carry whatever the agent attached to
/// the listening socket; `pid==0` means the agent couldn't resolve the
/// owner (common on Linux when the process is owned by another user
/// and /proc/<pid>/fd is unreadable).
struct ListenerSocket {
    std::string proto; ///< "tcp" / "tcp6" / "udp" / "udp6"
    int port{0};
    uint32_t pid{0};
    std::string process_name;
    /// Bind address as the kernel reports it (`0.0.0.0`, `::`, `127.0.0.1`,
    /// a NIC IP, etc.). The renderer uses this to drop loopback-only
    /// listeners (`127.0.0.0/8`, `::1`) from the cube-surface socket
    /// layer — those sockets are by definition not reachable from any
    /// other instance, so they don't belong on the inter-host surface.
    /// Empty when the agent didn't populate `local_addr` (older snapshots).
    /// Renderer treats absent/empty as non-loopback (safe-default — show
    /// rather than hide).
    ///
    /// **Field-name asymmetry note** (Gate 7 B-2): named `local_addr` to
    /// mirror the wire field `connections[i].local_addr` from the agent;
    /// semantically corresponds to `ConnectionEdge::src_addr` (the
    /// outbound side of a TCP flow). Both describe a host's local IP, but
    /// the LISTEN-row context names it `local_addr` and the
    /// ESTABLISHED-row context names it `src_addr`. Bounded at parse
    /// time to `kAddressMaxLen` (64 bytes) via the per-field cap in
    /// `parse_fleet_snapshot_json`.
    std::string local_addr;
};

/// One fleet machine -- a cube in the 3D scene.
struct MachineNode {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::vector<std::string> local_ips;
    std::vector<ProcessNode> processes;
    std::vector<ConnectionEdge> connections;
    std::vector<ListenerSocket> listeners;
    /// True when the agent failed to respond within the dispatch deadline
    /// or when the snapshot is older than the cache TTL. Renderer uses
    /// this to dim the cube and show "stale" overlay.
    bool stale{false};
    /// Epoch seconds when the agent emitted this snapshot. 0 when stale=true.
    int64_t ts{0};
    /// Truncation flags propagated from fleet_snapshot.v1.
    bool truncated_processes{false};
    bool truncated_connections{false};
};

/// Aggregate snapshot returned by FleetTopologyStore::get.
struct TopologySnapshot {
    int64_t generated_at{0};  ///< Server epoch seconds at build time
    bool include_vuln{false}; ///< Was the vuln overlay computed?
    std::vector<MachineNode> machines;
};

/// Single-host snapshot wrapper returned by `/api/v1/viz/host/<agent_id>/topology`.
/// Carries the same `generated_at` provenance as the fleet snapshot plus the
/// host-level `stale` flag promoted to the envelope so renderers can decide
/// whether to show a stale banner without reaching into `machine.stale`.
struct HostTopologySnapshot {
    int64_t generated_at{0};
    bool stale{false};
    MachineNode machine;
};

/// Input shape -- one parsed fleet_snapshot.v1 payload from a single agent.
/// SERVER-INTERNAL ONLY; never serialised to a renderer. The fetcher seam
/// produces a vector of these; FleetTopologyStore turns them into the
/// aggregate above. Carries `cmdline` (which MachineNode deliberately drops
/// post-redaction) so PR 7+ richer classification can use it.
struct RawAgentSnapshot {
    std::string agent_id;
    /// Full hostname (from snapshot).
    std::string hostname;
    /// OS reported by AgentRegistry session (snapshot doesn't carry it).
    std::string os;
    int64_t ts{0};
    std::vector<std::string> local_ips;
    bool truncated_processes{false};
    bool truncated_connections{false};
    /// Raw process rows from fleet_snapshot.v1 -- preserves cmdline so
    /// future PRs can use it for richer classification.
    struct RawProcess {
        uint32_t pid{0};
        uint32_t ppid{0};
        std::string name;
        std::string cmdline;
        std::string user;
    };
    std::vector<RawProcess> processes;
    struct RawConnection {
        std::string proto;
        std::string local_addr;
        int local_port{0};
        std::string remote_addr;
        std::string remote_host;
        int remote_port{0};
        std::string state;
        uint32_t pid{0};
        std::string process_name;
    };
    std::vector<RawConnection> connections;
    /// True when this agent timed out / errored during dispatch. Resulting
    /// MachineNode will have empty processes/connections and stale=true.
    bool stale{false};
    /// Server wall-clock epoch seconds when push_snapshot() accepted this
    /// snapshot. Distinct from `ts` (agent-controlled emit time) so neither
    /// the CAP-1 LRU victim selection nor the push-staleness gate can be
    /// skewed by an agent's clock (Gate 7 UP-4 / UP-14). 0 for snapshots
    /// produced by the dispatch fetcher (build_snapshot falls back to `ts`).
    int64_t server_received_at{0};
};

// ── JSON serialization (shape locked by tests) ────────────────────────────

inline void to_json(nlohmann::json& j, const ProcessNode& p) {
    j = {{"pid", p.pid},
         {"ppid", p.ppid},
         {"name", p.name},
         {"user", p.user},
         {"category", category_to_string(p.category)}};
    if (!p.worst_severity.empty()) {
        j["worst_severity"] = p.worst_severity;
        j["cve_count"] = p.cve_count;
    }
}

inline void to_json(nlohmann::json& j, const ConnectionEdge& e) {
    j = {{"proto", e.proto},
         {"src_pid", e.src_pid},
         {"src_addr", e.src_addr},
         {"src_port", e.src_port},
         {"dst_addr", e.dst_addr},
         {"dst_port", e.dst_port},
         {"scope", scope_to_string(e.scope)},
         {"state", e.state}};
    if (!e.dst_agent_id.empty())
        j["dst_agent_id"] = e.dst_agent_id;
    if (e.dst_pid != 0)
        j["dst_pid"] = e.dst_pid;
}

inline void to_json(nlohmann::json& j, const ListenerSocket& l) {
    j = {{"proto", l.proto}, {"port", l.port}};
    if (l.pid != 0)
        j["pid"] = l.pid;
    if (!l.process_name.empty())
        j["process_name"] = l.process_name;
    if (!l.local_addr.empty())
        j["local_addr"] = l.local_addr;
}

inline void to_json(nlohmann::json& j, const MachineNode& m) {
    j = {{"agent_id", m.agent_id},   {"hostname", m.hostname},   {"os", m.os},
         {"local_ips", m.local_ips}, {"processes", m.processes}, {"connections", m.connections},
         {"listeners", m.listeners}, {"stale", m.stale},         {"ts", m.ts}};
    if (m.truncated_processes)
        j["truncated_processes"] = true;
    if (m.truncated_connections)
        j["truncated_connections"] = true;
}

inline void to_json(nlohmann::json& j, const HostTopologySnapshot& s) {
    j = {{"schema", "host_topology.v1"},
         {"schema_minor", 1},
         {"generated_at", s.generated_at},
         {"stale", s.stale},
         {"machine", s.machine}};
}

inline void to_json(nlohmann::json& j, const TopologySnapshot& s) {
    // schema_minor allows additive evolution. Renderers MUST ignore unknown
    // keys. Bumped 1 -> 2 in PR 8 to advertise ConnectionEdge.dst_pid on
    // EdgeScope::Local edges.
    j = {{"schema", "fleet_topology.v1"},
         // schema_minor bump 3 → 4: ListenerSocket grows an optional
         // `local_addr` (bind address) field. Additive — older renderers
         // ignore. The renderer filters out loopback bind addresses so
         // only externally-reachable listeners appear on the cube surface.
         // Prior bumps: 2 → 3 added per-MachineNode `listeners` array
         // (PR 9 / UAT 2026-05-12); 1 → 2 added `dst_pid` on Local edges.
         {"schema_minor", 4},
         {"generated_at", s.generated_at},
         {"include_vuln", s.include_vuln},
         {"machines", s.machines}};
}

// Governance Gate 4 BLOCKING fix (#2146 Batch B3 review): clamp_field()
// truncates agent-reported hostname/process-name/user/connection fields by
// BYTE length (FleetTopologyStore::clamp_field), with no UTF-8 boundary
// awareness - a multi-byte codepoint straddling the cap is silently split
// into an invalid byte sequence. nlohmann::json::dump()'s strict default
// throws an uncaught type_error.316 on that input, and no exception handler
// is installed on web_server_ (documented at rest_api_v1.cpp and
// mcp_server.cpp), so the result is a bare empty-body 500 - fleet-wide for
// get_fleet_topology, per-host for get_host_topology - self-sustaining for as
// long as the offending agent stays connected. error_handler_t::replace
// substitutes U+FFFD for an invalid sequence instead of throwing, matching
// execution_statistics_model.cpp's own fix for the identical defect class.
// The ONE dump() call site every REST/MCP topology handler must route
// through, so the fix cannot drift between transports the way the original
// bug did.
inline std::string dump_topology_safe(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

} // namespace yuzu::server
