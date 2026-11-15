/**
 * echo_fleet_snapshot.cpp -- JSON builder for the echo.fleet_snapshot action.
 *
 * See echo_fleet_snapshot.hpp for the schema. Cmdline redaction reuses
 * redact_cmdline from echo_collectors.hpp; the same default patterns
 * (password/secret/token/api_key/credential) are applied as on the
 * regular collect_fast diff path.
 */

#include "echo_fleet_snapshot.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <tuple>
#include <unordered_set>

namespace yuzu::echo {

using json = nlohmann::json;

std::string build_fleet_snapshot_json(const std::vector<yuzu::agent::ProcessInfo>& processes,
                                      const std::vector<NetConnection>& connections,
                                      const std::vector<std::string>& local_ips,
                                      const std::string& hostname, int64_t ts,
                                      const std::vector<std::string>& redaction_patterns,
                                      bool process_source_enabled, bool tcp_source_enabled,
                                      int max_rows) {

    if (max_rows <= 0)
        max_rows = kFleetSnapshotMaxRows;

    const bool truncated_procs = processes.size() > static_cast<size_t>(max_rows);
    const bool truncated_conns = connections.size() > static_cast<size_t>(max_rows);

    const size_t proc_count = std::min(processes.size(), static_cast<size_t>(max_rows));
    const size_t conn_count = std::min(connections.size(), static_cast<size_t>(max_rows));

    json proc_arr = json::array();
    proc_arr.get_ref<json::array_t&>().reserve(proc_count);
    for (size_t i = 0; i < proc_count; ++i) {
        const auto& p = processes[i];
        proc_arr.push_back({{"pid", p.pid},
                            {"ppid", p.ppid},
                            {"name", p.name},
                            {"cmdline", redact_cmdline(p.cmdline, redaction_patterns)},
                            {"user", p.user}});
    }

    json conn_arr = json::array();
    conn_arr.get_ref<json::array_t&>().reserve(conn_count);
    for (size_t i = 0; i < conn_count; ++i) {
        const auto& c = connections[i];
        json row = {{"proto", c.proto},
                    {"local_addr", c.local_addr},
                    {"local_port", c.local_port},
                    {"remote_addr", c.remote_addr},
                    {"remote_host", c.remote_host},
                    {"remote_port", c.remote_port},
                    {"state", c.state},
                    {"pid", c.pid},
                    {"process_name", c.process_name}};
        // Omit when zero so live rows stay byte-identical with pre-PR-9-pre
        // snapshots — keeps the wire change strictly additive.
        if (c.last_seen_seconds_ago > 0)
            row["last_seen_seconds_ago"] = c.last_seen_seconds_ago;
        conn_arr.push_back(std::move(row));
    }

    json ips_arr = json::array();
    ips_arr.get_ref<json::array_t&>().reserve(local_ips.size());
    for (const auto& ip : local_ips)
        ips_arr.push_back(ip);

    json doc = {{"schema", "fleet_snapshot.v1"},
                // schema_minor bump 1 -> 2: connections[] gain an optional
                // `last_seen_seconds_ago` field for tcp_live-derived rows.
                // Additive — old readers ignore the new field. Old agents
                // never set it, so old snapshots round-trip unchanged.
                {"schema_minor", 2},
                {"ts", ts},
                {"hostname", hostname},
                {"local_ips", std::move(ips_arr)},
                {"processes", std::move(proc_arr)},
                {"connections", std::move(conn_arr)},
                {"truncated_processes", truncated_procs},
                {"truncated_connections", truncated_conns}};

    if (!process_source_enabled)
        doc["process_source_paused"] = true;
    if (!tcp_source_enabled)
        doc["tcp_source_paused"] = true;

    return doc.dump();
}

namespace {
struct FiveTupleKey {
    std::string proto;
    std::string local_addr;
    int local_port;
    std::string remote_addr;
    int remote_port;
    uint32_t pid;
    bool operator==(const FiveTupleKey& o) const = default;
};
struct FiveTupleHash {
    size_t operator()(const FiveTupleKey& k) const noexcept {
        // FNV-1a-ish mix; the field count is small enough that a hand-rolled
        // mix beats wrapping std::hash N times.
        size_t h = std::hash<std::string>{}(k.proto);
        auto mix = [&](size_t v) {
            h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        };
        mix(std::hash<std::string>{}(k.local_addr));
        mix(static_cast<size_t>(k.local_port));
        mix(std::hash<std::string>{}(k.remote_addr));
        mix(static_cast<size_t>(k.remote_port));
        mix(static_cast<size_t>(k.pid));
        return h;
    }
};
} // namespace

std::vector<NetConnection>
merge_live_and_recent_connections(const std::vector<NetConnection>& live,
                                  const std::vector<NetworkEvent>& recent, int64_t now_ts) {
    std::vector<NetConnection> out;
    out.reserve(live.size() + recent.size());

    std::unordered_set<FiveTupleKey, FiveTupleHash> seen;
    seen.reserve(live.size() + recent.size());

    for (const auto& c : live) {
        FiveTupleKey k{c.proto, c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.pid};
        seen.insert(k);
        out.push_back(c); // last_seen_seconds_ago stays at default 0 (live)
    }

    for (const auto& ev : recent) {
        FiveTupleKey k{ev.proto,       ev.local_addr,  ev.local_port,
                       ev.remote_addr, ev.remote_port, ev.pid};
        if (seen.contains(k))
            continue; // live row wins
        seen.insert(k);
        NetConnection c;
        c.proto = ev.proto;
        c.local_addr = ev.local_addr;
        c.local_port = ev.local_port;
        c.remote_addr = ev.remote_addr;
        c.remote_host = ev.remote_host;
        c.remote_port = ev.remote_port;
        c.state = ev.state;
        c.pid = ev.pid;
        c.process_name = ev.process_name;
        c.last_seen_seconds_ago = std::max<int64_t>(0, now_ts - ev.ts);
        out.push_back(std::move(c));
    }
    return out;
}

} // namespace yuzu::echo
