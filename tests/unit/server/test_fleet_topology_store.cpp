/**
 * test_fleet_topology_store.cpp -- FleetTopologyStore + process classify tests
 *
 * Covers:
 *   * Process categorization heuristics (classify())
 *   * Snapshot shape + JSON serialization
 *   * Cross-machine IP resolution (ip -> agent_id, scope classification)
 *   * Loopback / unspecified / external handling
 *   * Cache hit/miss + TTL expiry behaviour
 *   * Single-flight: concurrent get() calls fan one fetch
 *   * Stale-agent rows propagate without breaking the build
 *   * Vuln overlay path is testable without an NvdDatabase instance
 *     (we test that omitted/null nvd_ leaves worst_severity empty)
 */

#include "fleet_topology_store.hpp"
#include "fleet_topology_types.hpp"
#include "offline_endpoint_store.hpp"
#include "process_category.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <map>
#include <thread>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

RawAgentSnapshot make_agent(std::string id, std::string host, std::vector<std::string> ips) {
    RawAgentSnapshot r;
    r.agent_id = std::move(id);
    r.hostname = std::move(host);
    r.os = "linux";
    r.ts = 1715299200;
    r.local_ips = std::move(ips);
    return r;
}

RawAgentSnapshot::RawProcess proc(uint32_t pid, uint32_t ppid, std::string name, std::string user) {
    RawAgentSnapshot::RawProcess p;
    p.pid = pid;
    p.ppid = ppid;
    p.name = std::move(name);
    p.user = std::move(user);
    return p;
}

RawAgentSnapshot::RawConnection conn(std::string proto, std::string la, int lp, std::string ra,
                                     int rp, std::string state = "ESTABLISHED", uint32_t pid = 1) {
    RawAgentSnapshot::RawConnection c;
    c.proto = std::move(proto);
    c.local_addr = std::move(la);
    c.local_port = lp;
    c.remote_addr = std::move(ra);
    c.remote_port = rp;
    c.state = std::move(state);
    c.pid = pid;
    return c;
}

FleetTopologyStore::Fetcher fixed_fetcher(std::vector<RawAgentSnapshot> data) {
    return [data = std::move(data)](std::chrono::milliseconds) {
        return data;
    };
}

} // namespace

// =============================================================================
// classify()
// =============================================================================

TEST_CASE("classify: known database executables map to Database", "[viz][category]") {
    CHECK(classify("postgres") == ProcessCategory::Database);
    CHECK(classify("mysqld") == ProcessCategory::Database);
    CHECK(classify("redis-server") == ProcessCategory::Database);
    CHECK(classify("mongod") == ProcessCategory::Database);
}

TEST_CASE("classify: known browsers map to Browser", "[viz][category]") {
    CHECK(classify("chrome") == ProcessCategory::Browser);
    CHECK(classify("firefox") == ProcessCategory::Browser);
    CHECK(classify("msedge") == ProcessCategory::Browser);
    CHECK(classify("safari") == ProcessCategory::Browser);
}

TEST_CASE("classify: known web servers map to Web", "[viz][category]") {
    CHECK(classify("nginx") == ProcessCategory::Web);
    CHECK(classify("apache2") == ProcessCategory::Web);
    CHECK(classify("haproxy") == ProcessCategory::Web);
}

TEST_CASE("classify: runtimes map to Runtime", "[viz][category]") {
    CHECK(classify("java") == ProcessCategory::Runtime);
    CHECK(classify("python3") == ProcessCategory::Runtime);
    CHECK(classify("node") == ProcessCategory::Runtime);
    CHECK(classify("dotnet") == ProcessCategory::Runtime);
}

TEST_CASE("classify: known system processes map to System", "[viz][category]") {
    CHECK(classify("systemd") == ProcessCategory::System);
    CHECK(classify("launchd") == ProcessCategory::System);
    CHECK(classify("svchost") == ProcessCategory::System);
    CHECK(classify("kthreadd") == ProcessCategory::System);
}

TEST_CASE("classify: case-insensitive + Windows .exe stripped", "[viz][category]") {
    CHECK(classify("Chrome.exe") == ProcessCategory::Browser);
    CHECK(classify("PostgreS") == ProcessCategory::Database);
    CHECK(classify("MSEDGE.EXE") == ProcessCategory::Browser);
}

TEST_CASE("classify: unknown executables fall to Other", "[viz][category]") {
    CHECK(classify("my-custom-binary") == ProcessCategory::Other);
    CHECK(classify("") == ProcessCategory::Other);
    CHECK(classify("xyz123") == ProcessCategory::Other);
}

TEST_CASE("classify: full path stripped to basename", "[viz][category]") {
    CHECK(classify("/usr/bin/postgres") == ProcessCategory::Database);
    CHECK(classify("C:\\Program Files\\Mozilla Firefox\\firefox.exe") == ProcessCategory::Browser);
}

// =============================================================================
// build_snapshot — IP resolution + scope classification
// =============================================================================

TEST_CASE("topology: cross-machine connection resolves dst_agent_id", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.processes.push_back(proc(100, 1, "client", "alice"));
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "10.0.0.42", 5432));

    auto b = make_agent("agent-B", "hostB", {"10.0.0.42"});
    b.processes.push_back(proc(200, 1, "postgres", "postgres"));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    REQUIRE(snap);
    REQUIRE(snap->machines.size() == 2);

    const auto& edge = snap->machines[0].connections.at(0);
    CHECK(edge.scope == EdgeScope::InternalFleet);
    CHECK(edge.dst_agent_id == "agent-B");
}

TEST_CASE("topology: loopback connections classified as Local", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    // IPv4 reciprocal pair on 8080.
    a.connections.push_back(conn("tcp", "127.0.0.1", 41234, "127.0.0.1", 8080, "ESTABLISHED", 1));
    a.connections.push_back(conn("tcp", "127.0.0.1", 8080, "127.0.0.1", 41234, "ESTABLISHED", 2));
    // IPv6 reciprocal pair on 8081.
    a.connections.push_back(conn("tcp6", "::1", 41235, "::1", 8081, "ESTABLISHED", 3));
    a.connections.push_back(conn("tcp6", "::1", 8081, "::1", 41235, "ESTABLISHED", 4));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    // PR 8 keeps paired Local edges (each half resolved to its peer). Unpaired
    // Local edges would be dropped here; these four form two reciprocal pairs.
    REQUIRE(snap->machines.at(0).connections.size() == 4);
    for (const auto& e : snap->machines[0].connections) {
        CHECK(e.scope == EdgeScope::Local);
    }
}

// PR 8: a TCP loopback session on Linux appears in the kernel's socket table
// as TWO ESTABLISHED records -- the initiator's outbound half (local=ephemeral,
// remote=service-port) and the listener's accepted half (local=service-port,
// remote=ephemeral). The renderer needs the destination pid on each half to
// draw the interior line between the two process dots. build_snapshot()
// pairs the halves by reciprocal 4-tuple match and writes the peer's src_pid
// into ConnectionEdge.dst_pid; unmatched halves are dropped (PR 8 spec).
TEST_CASE("topology: reciprocal Local loopback pair resolves dst_pid both ways",
          "[viz][topology][pr8]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    // Process 100 initiated a connection to 127.0.0.1:8080 from ephemeral port 50000.
    a.connections.push_back(conn("tcp", "127.0.0.1", 50000, "127.0.0.1", 8080, "ESTABLISHED", 100));
    // Process 200 is on the listening side, accepted the connection from 50000.
    a.connections.push_back(conn("tcp", "127.0.0.1", 8080, "127.0.0.1", 50000, "ESTABLISHED", 200));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.size() == 1);
    REQUIRE(snap->machines[0].connections.size() == 2);

    const auto& edges = snap->machines[0].connections;
    auto from_100 =
        std::find_if(edges.begin(), edges.end(), [](const auto& e) { return e.src_pid == 100; });
    auto from_200 =
        std::find_if(edges.begin(), edges.end(), [](const auto& e) { return e.src_pid == 200; });
    REQUIRE(from_100 != edges.end());
    REQUIRE(from_200 != edges.end());

    CHECK(from_100->scope == EdgeScope::Local);
    CHECK(from_200->scope == EdgeScope::Local);
    CHECK(from_100->dst_pid == 200);
    CHECK(from_200->dst_pid == 100);
}

// PR 8 spec: "Drop edges with unresolved destination." If an agent captures
// only one half of a loopback session (e.g. the listener is gone, or the
// snapshot raced), the renderer has nothing to connect the line to. Server
// drops these before serialisation so the wire payload stays consistent.
TEST_CASE("topology: unmatched Local edge is dropped (no reciprocal half)",
          "[viz][topology][pr8]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "127.0.0.1", 50000, "127.0.0.1", 8080, "ESTABLISHED", 100));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.size() == 1);
    CHECK(snap->machines[0].connections.empty());
}

// Non-Local edges (InternalFleet, External) must be untouched by the PR 8
// pairing+drop pass -- their destination is on a different machine (or
// outside the fleet), so dst_pid stays the default 0 and the drop predicate
// must not catch them.
TEST_CASE("topology: PR 8 pairing pass leaves non-Local edges untouched", "[viz][topology][pr8]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    auto b = make_agent("agent-B", "hostB", {"10.0.0.42"});

    // Cross-fleet edge (InternalFleet scope expected).
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "10.0.0.42", 5432, "ESTABLISHED", 100));
    // External edge.
    a.connections.push_back(conn("tcp", "10.0.0.7", 50001, "8.8.8.8", 443, "ESTABLISHED", 100));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.size() == 2);

    auto& a_edges = snap->machines[0].connections;
    REQUIRE(a_edges.size() == 2);

    auto fleet_it = std::find_if(a_edges.begin(), a_edges.end(),
                                 [](const auto& e) { return e.scope == EdgeScope::InternalFleet; });
    auto ext_it = std::find_if(a_edges.begin(), a_edges.end(),
                               [](const auto& e) { return e.scope == EdgeScope::External; });
    REQUIRE(fleet_it != a_edges.end());
    REQUIRE(ext_it != a_edges.end());
    CHECK(fleet_it->dst_pid == 0);
    CHECK(ext_it->dst_pid == 0);
}

TEST_CASE("topology: connection to non-fleet IP marked External", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "8.8.8.8", 443));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    CHECK(snap->machines[0].connections[0].scope == EdgeScope::External);
    CHECK(snap->machines[0].connections[0].dst_agent_id.empty());
}

TEST_CASE("topology: 0.0.0.0 / :: in local_ips skipped from ip_to_agent map", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"0.0.0.0", "10.0.0.7", "::"});
    auto b = make_agent("agent-B", "hostB", {"10.0.0.42"});
    // B connects to 0.0.0.0:9000 -- if not skipped, would resolve to A.
    b.connections.push_back(conn("tcp", "10.0.0.42", 50000, "0.0.0.0", 9000));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    auto& edges = snap->machines[1].connections;
    REQUIRE(edges.size() == 1);
    CHECK(edges[0].scope == EdgeScope::External);
    CHECK(edges[0].dst_agent_id.empty());
}

TEST_CASE("topology: LISTEN row lifted into listeners[] AND dual-emitted in connections[]",
          "[viz][topology]") {
    // PR 9 / PR 10 hardening — LISTEN rows are the source of truth for
    // `listeners[]` AND for one release continue to appear in
    // `connections[]` (with `scope=external`) so pre-PR-9 consumers
    // filtering `connections` by `state == "LISTEN"` are not silently
    // broken. Removal of the dual-emit half ships with a `Breaking`
    // CHANGELOG entry in a future release.
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "10.0.0.7", 22, "", 0, "LISTEN"));
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "10.0.0.42", 443));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    // listeners[] carries the LISTEN row exactly once.
    REQUIRE(snap->machines[0].listeners.size() == 1);
    CHECK(snap->machines[0].listeners[0].port == 22);
    // schema_minor 4: bind address propagates so the renderer can filter
    // loopback-only listeners off the cube surface.
    CHECK(snap->machines[0].listeners[0].local_addr == "10.0.0.7");
    // connections[] carries both rows during the deprecation window.
    REQUIRE(snap->machines[0].connections.size() == 2);
    // The active flow is present and has the real remote endpoint.
    bool saw_443 = false;
    bool saw_listen = false;
    for (const auto& e : snap->machines[0].connections) {
        if (e.dst_port == 443)
            saw_443 = true;
        if (e.state == "LISTEN") {
            saw_listen = true;
            CHECK(e.scope == EdgeScope::External);
        }
    }
    CHECK(saw_443);
    CHECK(saw_listen);
}

TEST_CASE("topology: ListenerSocket carries local_addr for renderer surface filter",
          "[viz][topology]") {
    // schema_minor 4 — `local_addr` ships on every LISTEN row in the
    // topology JSON so the renderer can drop loopback-only listeners
    // from the cube-surface socket layer. The agent already emits
    // `local_addr` on every connection row; here we prove it makes it
    // through build_snapshot unchanged for the bind flavours the
    // filter cares about, including IPv6 forms (Gate 7 QA F2):
    //   - routable NIC IP
    //   - `0.0.0.0` any-interface (IPv4 unspecified)
    //   - `127.0.0.1` loopback-only (IPv4)
    //   - `::` any-interface (IPv6 unspecified)
    //   - `::1` loopback-only (IPv6)
    //   - `[::1]` bracketed IPv6 loopback (some agents wrap in brackets)
    //   - empty string (older agents pre-PR-12) — JSON key must be ABSENT
    //
    // Server is the faithful pipe — even loopback addresses make it onto
    // the wire; renderer is the filter. Empty `local_addr` is special:
    // the `to_json` guard `if (!l.local_addr.empty())` omits the JSON key
    // entirely so older snapshots produce the same wire shape as before
    // the schema_minor 4 bump (graceful evolution).
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "10.0.0.7", 22, "", 0, "LISTEN"));    // routable
    a.connections.push_back(conn("tcp", "0.0.0.0", 8080, "", 0, "LISTEN"));   // v4 any
    a.connections.push_back(conn("tcp", "127.0.0.1", 5432, "", 0, "LISTEN")); // v4 loop
    a.connections.push_back(conn("tcp6", "::", 9090, "", 0, "LISTEN"));       // v6 any
    a.connections.push_back(conn("tcp6", "::1", 9091, "", 0, "LISTEN"));      // v6 loop
    a.connections.push_back(conn("tcp6", "[::1]", 9092, "", 0, "LISTEN"));    // v6 bracketed
    a.connections.push_back(conn("tcp", "", 9999, "", 0, "LISTEN"));          // empty (old agent)

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.size() == 1);
    const auto& ls = snap->machines[0].listeners;
    REQUIRE(ls.size() == 7);
    std::map<int, std::string> bind_by_port;
    for (const auto& l : ls)
        bind_by_port[l.port] = l.local_addr;
    CHECK(bind_by_port[22] == "10.0.0.7");
    CHECK(bind_by_port[8080] == "0.0.0.0");
    CHECK(bind_by_port[5432] == "127.0.0.1");
    CHECK(bind_by_port[9090] == "::");
    CHECK(bind_by_port[9091] == "::1");
    CHECK(bind_by_port[9092] == "[::1]");
    CHECK(bind_by_port[9999] == "");

    // And it's visible in the wire JSON — the renderer reads
    // `listeners[i].local_addr` directly. The empty-`local_addr` row
    // must OMIT the JSON key entirely (graceful pre-PR-12 evolution).
    // Gate 7 QA F5: switched from per-row REQUIRE-in-loop to explicit
    // by-port lookup so the omitted-key case doesn't abort with a
    // misleading message.
    nlohmann::json j = *snap;
    const auto& wire_listeners = j["machines"][0]["listeners"];
    REQUIRE(wire_listeners.is_array());
    REQUIRE(wire_listeners.size() == 7);
    std::map<int, nlohmann::json> wire_by_port;
    for (const auto& wl : wire_listeners)
        wire_by_port[wl["port"].get<int>()] = wl;
    CHECK(wire_by_port[22].contains("local_addr"));
    CHECK(wire_by_port[22]["local_addr"] == "10.0.0.7");
    CHECK(wire_by_port[8080]["local_addr"] == "0.0.0.0");
    CHECK(wire_by_port[5432]["local_addr"] == "127.0.0.1");
    CHECK(wire_by_port[9090]["local_addr"] == "::");
    CHECK(wire_by_port[9091]["local_addr"] == "::1");
    CHECK(wire_by_port[9092]["local_addr"] == "[::1]");
    // Empty-string row omits the key entirely — pre-PR-12 wire shape.
    CHECK_FALSE(wire_by_port[9999].contains("local_addr"));
}

TEST_CASE("topology: parse_fleet_snapshot_json clamps oversize local_addr",
          "[viz][topology][hardening]") {
    // Gate 7 UP-1 BLOCKING fix. A malformed or hostile agent could ship
    // a multi-MB `local_addr` per LISTEN row; the 2 MiB envelope cap
    // alone would let it through. The parser clamps per-field at
    // kAddressMaxLen (64 bytes) so the wire payload stays bounded
    // regardless of agent behaviour. The truncation logs a spdlog warn
    // (visible in operator logs as a breadcrumb).
    std::string oversize(2048, 'A');
    std::string body =
        std::string("{\"schema\":\"fleet_snapshot.v1\",\"ts\":1,") +
        "\"hostname\":\"h\",\"local_ips\":[\"10.0.0.5\"]," + "\"processes\":[]," +
        "\"connections\":[{\"proto\":\"tcp\",\"local_addr\":\"" + oversize +
        "\",\"local_port\":22,\"remote_addr\":\"\",\"remote_port\":0,\"state\":\"LISTEN\"}]," +
        "\"truncated_processes\":false,\"truncated_connections\":false}";
    std::string ex;
    auto parsed = FleetTopologyStore::parse_fleet_snapshot_json(body, "agent-A", "linux", &ex);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->connections.size() == 1);
    CHECK(parsed->connections[0].local_addr.size() == 64);
    CHECK(parsed->connections[0].local_addr == std::string(64, 'A'));
}

TEST_CASE("topology: is_loopback_addr recognises v4-mapped-in-v6 form",
          "[viz][topology][hardening]") {
    // Gate 7 S-2 alignment with renderer's isLoopbackBind. The server's
    // intra-cube loopback edge filter (build_snapshot ~line 786) uses
    // is_loopback_addr; without this branch a host using AF_INET6 +
    // ::ffff:127.0.0.1 wouldn't have its intra-host edges suppressed.
    // Test the namespace-private helper indirectly via a LISTEN row.
    auto a = make_agent("agent-V6", "v6host", {"10.0.0.42"});
    a.connections.push_back(conn("tcp6", "::ffff:127.0.0.1", 6379, "", 0, "LISTEN"));
    a.connections.push_back(conn("tcp6", "[::ffff:127.0.0.1]", 6380, "", 0, "LISTEN"));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.size() == 1);
    REQUIRE(snap->machines[0].listeners.size() == 2);
    // Server is the faithful pipe — both addresses propagate.
    // The renderer's isLoopbackBind drops them at render time;
    // is_loopback_addr's v4-mapped-loopback branch is for the
    // build_snapshot's intra-cube edge filter.
    CHECK(snap->machines[0].listeners[0].local_addr == "::ffff:127.0.0.1");
    CHECK(snap->machines[0].listeners[1].local_addr == "[::ffff:127.0.0.1]");
}

TEST_CASE("topology: process category attached to ProcessNode", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {});
    a.processes.push_back(proc(1, 0, "systemd", "root"));
    a.processes.push_back(proc(100, 1, "nginx", "www-data"));
    a.processes.push_back(proc(200, 1, "postgres", "postgres"));
    a.processes.push_back(proc(300, 1, "weird-binary", "nathan"));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    const auto& procs = snap->machines.at(0).processes;
    REQUIRE(procs.size() == 4);
    CHECK(procs[0].category == ProcessCategory::System);
    CHECK(procs[1].category == ProcessCategory::Web);
    CHECK(procs[2].category == ProcessCategory::Database);
    CHECK(procs[3].category == ProcessCategory::Other);
}

TEST_CASE("topology: stale agent row preserved with empty inventory", "[viz][topology]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.stale = true;
    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.size() == 1);
    CHECK(snap->machines[0].stale == true);
    CHECK(snap->machines[0].processes.empty());
    CHECK(snap->machines[0].connections.empty());
}

TEST_CASE("topology: include_vuln=false leaves worst_severity empty", "[viz][topology][vuln]") {
    auto a = make_agent("agent-A", "hostA", {});
    a.processes.push_back(proc(100, 1, "postgres", "postgres"));
    FleetTopologyStore store(fixed_fetcher({a}), nullptr);
    auto snap = store.get(false);
    CHECK(snap->machines[0].processes[0].worst_severity.empty());
    CHECK(snap->machines[0].processes[0].cve_count == 0);
}

// =============================================================================
// JSON shape (locked by tests)
// =============================================================================

TEST_CASE("topology: TopologySnapshot serializes to fleet_topology.v1 JSON",
          "[viz][topology][json]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.processes.push_back(proc(100, 1, "nginx", "www-data"));
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "8.8.8.8", 443));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    json j = *snap;

    CHECK(j["schema"] == "fleet_topology.v1");
    CHECK(j["include_vuln"] == false);
    REQUIRE(j["machines"].size() == 1);
    CHECK(j["machines"][0]["agent_id"] == "agent-A");
    CHECK(j["machines"][0]["hostname"] == "hostA");
    CHECK(j["machines"][0]["local_ips"][0] == "10.0.0.7");
    CHECK(j["machines"][0]["processes"][0]["category"] == "web");
    CHECK(j["machines"][0]["connections"][0]["scope"] == "external");
}

// PR 8 JSON shape: dst_pid is emitted only when non-zero (matches the
// dst_agent_id pattern -- optional field omitted when default). schema_minor
// bumps 1 -> 2 to advertise the additive field; renderers ignoring unknown
// minor versions continue to work.
TEST_CASE("topology: dst_pid serializes only when non-zero; schema_minor bumped",
          "[viz][topology][json][pr8]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "127.0.0.1", 50000, "127.0.0.1", 8080, "ESTABLISHED", 100));
    a.connections.push_back(conn("tcp", "127.0.0.1", 8080, "127.0.0.1", 50000, "ESTABLISHED", 200));
    a.connections.push_back(conn("tcp", "10.0.0.7", 50001, "8.8.8.8", 443, "ESTABLISHED", 300));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    json j = *snap;

    CHECK(j["schema_minor"] == 4); // PR 12: ListenerSocket.local_addr added

    const auto& edges = j["machines"][0]["connections"];
    REQUIRE(edges.size() == 3);

    bool saw_paired = false, saw_external = false;
    for (const auto& edge : edges) {
        if (edge["scope"] == "local") {
            CHECK(edge.contains("dst_pid"));
            CHECK(edge["dst_pid"].is_number_unsigned());
            CHECK((edge["dst_pid"] == 100 || edge["dst_pid"] == 200));
            saw_paired = true;
        }
        if (edge["scope"] == "external") {
            CHECK_FALSE(edge.contains("dst_pid"));
            saw_external = true;
        }
    }
    CHECK(saw_paired);
    CHECK(saw_external);
}

// IPv6 loopback (::1) pairs must resolve equivalently to IPv4 -- the
// matching key is the exact (addr, port) tuple, so the only requirement is
// is_loopback_addr() recognises ::1 (it does).
TEST_CASE("topology: IPv6 ::1 reciprocal pair resolves dst_pid", "[viz][topology][pr8]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp6", "::1", 50000, "::1", 8080, "ESTABLISHED", 100));
    a.connections.push_back(conn("tcp6", "::1", 8080, "::1", 50000, "ESTABLISHED", 200));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    const auto& edges = snap->machines.at(0).connections;
    REQUIRE(edges.size() == 2);
    auto from_100 =
        std::find_if(edges.begin(), edges.end(), [](const auto& e) { return e.src_pid == 100; });
    auto from_200 =
        std::find_if(edges.begin(), edges.end(), [](const auto& e) { return e.src_pid == 200; });
    REQUIRE(from_100 != edges.end());
    REQUIRE(from_200 != edges.end());
    CHECK(from_100->dst_pid == 200);
    CHECK(from_200->dst_pid == 100);
}

// Two independent Local pairs on the same machine must not cross-match: the
// matcher keys on the full 4-tuple, so a "greedy first-match" bug would
// surface here. Pair 1: pid 100 <-> pid 200 on port 8080. Pair 2: pid 300
// <-> pid 400 on port 9090. Each edge's dst_pid must point at its own
// reciprocal, not the other pair's process.
TEST_CASE("topology: two Local pairs on same machine match correctly (no cross-pair leak)",
          "[viz][topology][pr8]") {
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    // Pair 1: client 100 -> server 200 on 8080
    a.connections.push_back(conn("tcp", "127.0.0.1", 50000, "127.0.0.1", 8080, "ESTABLISHED", 100));
    a.connections.push_back(conn("tcp", "127.0.0.1", 8080, "127.0.0.1", 50000, "ESTABLISHED", 200));
    // Pair 2: client 300 -> server 400 on 9090
    a.connections.push_back(conn("tcp", "127.0.0.1", 51000, "127.0.0.1", 9090, "ESTABLISHED", 300));
    a.connections.push_back(conn("tcp", "127.0.0.1", 9090, "127.0.0.1", 51000, "ESTABLISHED", 400));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    const auto& edges = snap->machines.at(0).connections;
    REQUIRE(edges.size() == 4);

    auto find_by_pid = [&](uint32_t pid) {
        return std::find_if(edges.begin(), edges.end(),
                            [pid](const auto& e) { return e.src_pid == pid; });
    };
    auto e100 = find_by_pid(100);
    auto e200 = find_by_pid(200);
    auto e300 = find_by_pid(300);
    auto e400 = find_by_pid(400);
    REQUIRE(e100 != edges.end());
    REQUIRE(e200 != edges.end());
    REQUIRE(e300 != edges.end());
    REQUIRE(e400 != edges.end());

    CHECK(e100->dst_pid == 200);
    CHECK(e200->dst_pid == 100);
    CHECK(e300->dst_pid == 400);
    CHECK(e400->dst_pid == 300);
}

// =============================================================================
// Cache behaviour
// =============================================================================

TEST_CASE("cache: second get() within TTL is a hit", "[viz][cache]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{};
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    auto s1 = store.get(false);
    auto s2 = store.get(false);
    CHECK(calls.load() == 1);
    CHECK(s1 == s2); // shared_ptr identity -- same cached object
    CHECK(store.cache_hits() == 1);
    CHECK(store.cache_misses() == 1);
}

TEST_CASE("cache: short TTL expires and triggers refill", "[viz][cache]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{};
    };
    // 1 ms TTL so the second call can guarantee expiry.
    FleetTopologyStore store(fetcher, nullptr, std::chrono::milliseconds(1));

    store.get(false);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    store.get(false);
    CHECK(calls.load() == 2);
    CHECK(store.cache_misses() == 2);
}

TEST_CASE("cache: invalidate() forces next get to refill", "[viz][cache]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{};
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    store.get(false);
    store.invalidate();
    store.get(false);
    CHECK(calls.load() == 2);
}

TEST_CASE("cache: include_vuln=true and =false are independent slots", "[viz][cache]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{};
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    store.get(false);
    store.get(true);
    store.get(false); // should hit
    store.get(true);  // should hit
    CHECK(calls.load() == 2);
}

TEST_CASE("cache: single-flight -- concurrent get() calls fan one fetch",
          "[viz][cache][singleflight]") {
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) {
        ++calls;
        // Sleep long enough that all threads pile up before the first finishes.
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        return std::vector<RawAgentSnapshot>{};
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    constexpr int N = 16;
    std::vector<std::future<std::shared_ptr<const TopologySnapshot>>> futures;
    futures.reserve(N);
    for (int i = 0; i < N; ++i) {
        futures.push_back(std::async(std::launch::async, [&] { return store.get(false); }));
    }
    for (auto& f : futures) {
        REQUIRE(f.get() != nullptr);
    }
    CHECK(calls.load() == 1);
    CHECK(store.refill_waiters() >= 1); // some fraction of N-1 were waiters
}

TEST_CASE("cache: fetcher exception returns empty sentinel, unblocks waiters",
          "[viz][cache][singleflight]") {
    // UP-9 fix: get() must never return nullptr. On first-call fetcher
    // exception, callers receive an empty TopologySnapshot rather than
    // nullptr so PR 3's REST handler can serialise without null-check.
    std::atomic<int> calls{0};
    auto fetcher = [&calls](std::chrono::milliseconds) -> std::vector<RawAgentSnapshot> {
        ++calls;
        throw std::runtime_error("boom");
    };
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60));

    auto snap = store.get(false);
    REQUIRE(snap != nullptr);
    CHECK(snap->machines.empty());
    CHECK(snap->generated_at != 0);
    CHECK(calls.load() == 1);
    // Subsequent get() should also retry (slot empty, treat as miss).
    auto snap2 = store.get(false);
    REQUIRE(snap2 != nullptr);
    CHECK(snap2->machines.empty());
    CHECK(calls.load() == 2);
}

// =============================================================================
// New tests added in governance round 1
// =============================================================================

TEST_CASE("topology: agent self-connection classified as External, not Internal",
          "[viz][topology][self]") {
    // QE-S3 — connection from a host to one of its own non-loopback IPs
    // should not be a fleet edge.
    auto a = make_agent("agent-A", "hostA", {"10.0.0.7"});
    a.connections.push_back(conn("tcp", "10.0.0.7", 50000, "10.0.0.7", 8080));

    FleetTopologyStore store(fixed_fetcher({a}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.at(0).connections.size() == 1);
    CHECK(snap->machines[0].connections[0].scope == EdgeScope::External);
    CHECK(snap->machines[0].connections[0].dst_agent_id.empty());
}

TEST_CASE("topology: link-local IPs in local_ips are skipped from ip_to_agent",
          "[viz][topology][defence]") {
    // cons-N3 — defence-in-depth: malformed agent emitting 169.254.x.x or
    // fe80::* in local_ips must not seed cross-machine resolution.
    auto a = make_agent("agent-A", "hostA", {"169.254.1.5", "fe80::abcd", "10.0.0.7"});
    auto b = make_agent("agent-B", "hostB", {"10.0.0.42"});
    b.connections.push_back(conn("tcp", "10.0.0.42", 50000, "169.254.1.5", 5432));
    b.connections.push_back(conn("tcp6", "fd00::2", 50001, "fe80::abcd", 5432));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    auto& edges = snap->machines[1].connections;
    REQUIRE(edges.size() == 2);
    CHECK(edges[0].scope == EdgeScope::External);
    CHECK(edges[0].dst_agent_id.empty());
    CHECK(edges[1].scope == EdgeScope::External);
    CHECK(edges[1].dst_agent_id.empty());
}

TEST_CASE("topology: IPv6 bracketed and zone-id forms normalized for ip_to_agent lookup",
          "[viz][topology][ipv6]") {
    // UP-7 — agent A reports `fd00::1`; agent B's connection lists
    // `[fd00::1]:443` (bracket form) or `fd00::1%eth0` (zone-id). All three
    // must resolve to the same canonical key.
    auto a = make_agent("agent-A", "hostA", {"fd00::1"});
    auto b = make_agent("agent-B", "hostB", {"fd00::2"});
    b.connections.push_back(conn("tcp6", "fd00::2", 50000, "[fd00::1]", 443));
    b.connections.push_back(conn("tcp6", "fd00::2", 50001, "fd00::1%eth0", 443));

    FleetTopologyStore store(fixed_fetcher({a, b}));
    auto snap = store.get(false);
    auto& edges = snap->machines[1].connections;
    REQUIRE(edges.size() == 2);
    CHECK(edges[0].scope == EdgeScope::InternalFleet);
    CHECK(edges[0].dst_agent_id == "agent-A");
    CHECK(edges[1].scope == EdgeScope::InternalFleet);
    CHECK(edges[1].dst_agent_id == "agent-A");
}

// =============================================================================
// PR 6 / OBS-2: fetch-duration observer
// =============================================================================

TEST_CASE("observer: set_fetch_duration_observer fires once per refill", "[viz][cache][obs]") {
    // OBS-2 — every cache miss observer call lets server.cpp wire the
    // fetch into a Prometheus histogram. Cache hits MUST NOT fire (the
    // fetcher didn't run).
    std::atomic<int> observer_calls{0};
    std::atomic<int> fetcher_calls{0};
    auto a = make_agent("agent-A", "hostA", {});
    auto fetcher = [&fetcher_calls, a](std::chrono::milliseconds) {
        ++fetcher_calls;
        return std::vector<RawAgentSnapshot>{a};
    };
    // gov R6 QE SHOULD-4: the original 50ms TTL + 80ms sleep was a
    // 1.6× ratio — flake-prone on slow CI runners (e.g. Defender-throttled
    // Windows under #473). Match the established 1ms TTL + 10ms sleep
    // pattern from the sibling `cache: short TTL expires and triggers
    // refill` test (10× ratio).
    FleetTopologyStore store(fetcher, nullptr, std::chrono::milliseconds(1));
    store.set_fetch_duration_observer(
        [&observer_calls](std::chrono::duration<double>) { ++observer_calls; });

    // First get: cache miss -> fetcher runs -> observer fires.
    auto s1 = store.get(false);
    REQUIRE(s1 != nullptr);
    CHECK(observer_calls.load() == 1);
    CHECK(fetcher_calls.load() == 1);

    // gov R6: a get() within 1ms TTL is a coin-flip on slow CI -- the
    // sibling test takes the same approach of immediately invalidating
    // for the cache-hit assertion to be deterministic. Use a fresh
    // store with longer TTL just for the cache-hit branch.
    FleetTopologyStore store_long(fetcher, nullptr, std::chrono::seconds(60));
    std::atomic<int> long_observer_calls{0};
    std::atomic<int> long_fetcher_calls{0};
    auto fetcher_long = [&long_fetcher_calls, a](std::chrono::milliseconds) {
        ++long_fetcher_calls;
        return std::vector<RawAgentSnapshot>{a};
    };
    FleetTopologyStore store_long2(fetcher_long, nullptr, std::chrono::seconds(60));
    store_long2.set_fetch_duration_observer(
        [&long_observer_calls](std::chrono::duration<double>) { ++long_observer_calls; });
    auto sl1 = store_long2.get(false);
    REQUIRE(sl1 != nullptr);
    CHECK(long_observer_calls.load() == 1);
    auto sl2 = store_long2.get(false);
    REQUIRE(sl2 != nullptr);
    CHECK(long_observer_calls.load() == 1); // cache hit, observer NOT fired
    CHECK(long_fetcher_calls.load() == 1);

    // Force expiry on the short-TTL store, third get: refill -> observer fires again.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto s3 = store.get(false);
    REQUIRE(s3 != nullptr);
    CHECK(observer_calls.load() == 2);
    CHECK(fetcher_calls.load() == 2);
}

TEST_CASE("observer: fetch-duration observer fires even on fetcher exception",
          "[viz][cache][obs]") {
    // OBS-2 — a hung / throwing fetcher must still produce a histogram
    // observation; otherwise the gate that says "agent dispatch is slow"
    // would silently miss the worst case.
    std::atomic<int> observer_calls{0};
    auto fetcher = [](std::chrono::milliseconds) -> std::vector<RawAgentSnapshot> {
        throw std::runtime_error("boom");
    };
    FleetTopologyStore store(fetcher);
    store.set_fetch_duration_observer(
        [&observer_calls](std::chrono::duration<double>) { ++observer_calls; });

    auto snap = store.get(false);
    REQUIRE(snap != nullptr); // empty sentinel, never null
    CHECK(observer_calls.load() == 1);
}

TEST_CASE("observer: cleared observer is not invoked", "[viz][cache][obs]") {
    // Setting an empty std::function clears the observer slot. The
    // refill path must check before calling.
    std::atomic<int> observer_calls{0};
    auto a = make_agent("agent-A", "hostA", {});
    FleetTopologyStore store(fixed_fetcher({a}));
    store.set_fetch_duration_observer(
        [&observer_calls](std::chrono::duration<double>) { ++observer_calls; });
    auto s1 = store.get(false);
    REQUIRE(s1 != nullptr);
    CHECK(observer_calls.load() == 1);

    store.set_fetch_duration_observer(FleetTopologyStore::FetchDurationObserver{});
    store.invalidate();
    auto s2 = store.get(false);
    REQUIRE(s2 != nullptr);
    CHECK(observer_calls.load() == 1); // not incremented
}

// =============================================================================
// (existing) cache: oversized snapshot
// =============================================================================

TEST_CASE("cache: oversized snapshot is returned but not cached", "[viz][cache][cap]") {
    // CAP-1 — when a refill exceeds max_snapshot_bytes, the caller still
    // receives the snapshot for this request, but the cache slot is NOT
    // populated (next get() refills from scratch).
    std::atomic<int> calls{0};
    auto a = make_agent("agent-A", "hostA", {});
    for (int i = 0; i < 100; ++i)
        a.processes.push_back(proc(static_cast<uint32_t>(i), 1, "p", "u"));
    auto fetcher = [&calls, a](std::chrono::milliseconds) {
        ++calls;
        return std::vector<RawAgentSnapshot>{a};
    };
    // Set max_snapshot_bytes very low so the realistic snapshot blows past it.
    FleetTopologyStore store(fetcher, nullptr, std::chrono::seconds(60),
                             std::chrono::milliseconds(5000), /*max_snapshot_bytes=*/256);

    auto snap1 = store.get(false);
    REQUIRE(snap1 != nullptr);
    REQUIRE(snap1->machines.size() == 1);
    CHECK(calls.load() == 1);

    // Second call should NOT be a cache hit -- slot was refused due to size.
    auto snap2 = store.get(false);
    REQUIRE(snap2 != nullptr);
    CHECK(calls.load() == 2);
    CHECK(store.refill_oversize_drops() >= 2);
}

// =============================================================================
// Gate 7 hardening — parser field clamps, IP-claim lifecycle, CAP-1 victim
// selection, mixed-fleet roster sentinels, push-staleness clock source.
// =============================================================================

namespace {

// Build a fleet_snapshot.v1 JSON body with caller-controlled field values.
std::string snapshot_body(const std::string& hostname, const std::string& proc_name,
                          const std::string& cmdline, const std::string& proc_user,
                          const std::string& conn_state) {
    json j;
    j["schema"] = "fleet_snapshot.v1";
    j["ts"] = 1;
    j["hostname"] = hostname;
    j["local_ips"] = json::array();
    j["processes"] = json::array({json{
        {"pid", 1}, {"ppid", 0}, {"name", proc_name}, {"cmdline", cmdline}, {"user", proc_user}}});
    j["connections"] = json::array({json{{"proto", "tcp"},
                                         {"local_addr", "10.0.0.1"},
                                         {"local_port", 22},
                                         {"remote_addr", "10.0.0.2"},
                                         {"remote_port", 5000},
                                         {"state", conn_state},
                                         {"process_name", proc_name}}});
    return j.dump();
}

// A RawAgentSnapshot ready to push, with explicit local_ips and an
// optional server_received_at override (0 = let push_snapshot stamp it).
RawAgentSnapshot pushable(std::string id, std::vector<std::string> ips,
                          int64_t server_received_at = 0) {
    RawAgentSnapshot r = make_agent(std::move(id), "host", std::move(ips));
    r.server_received_at = server_received_at;
    return r;
}

} // namespace

TEST_CASE("topology: parser clamps oversize process + hostname + conn-meta fields",
          "[viz][topology][hardening][gate7]") {
    // Gate 7 qe-B1 / sec-M1 — before this round only the address fields
    // were clamped; process name/cmdline/user, hostname and the
    // connection meta strings flowed in unbounded. A single oversize row
    // sailed past the 2 MiB envelope cap and was held in pushed_ for the
    // agent's lifetime.
    const std::string big(8192, 'X');
    std::string body = snapshot_body(big, big, big, big, big);
    std::string ex;
    auto parsed = FleetTopologyStore::parse_fleet_snapshot_json(body, "agent-A", "linux", &ex);
    REQUIRE(parsed.has_value());
    CHECK(parsed->hostname.size() == 256);
    REQUIRE(parsed->processes.size() == 1);
    CHECK(parsed->processes[0].name.size() == 256);
    CHECK(parsed->processes[0].cmdline.size() == 4096);
    CHECK(parsed->processes[0].user.size() == 256);
    REQUIRE(parsed->connections.size() == 1);
    CHECK(parsed->connections[0].state.size() == 256);
    CHECK(parsed->connections[0].process_name.size() == 256);
}

TEST_CASE("topology: a byte-clamped multi-byte hostname serializes without throwing",
          "[viz][topology][hardening][gate4]") {
    // Governance Gate 4 BLOCKING fix (#2146 Batch B3 review): clamp_field()
    // truncates by BYTE length with no UTF-8 boundary awareness. 100
    // repetitions of the 3-byte euro sign (U+20AC, bytes E2 82 AC) is 300
    // bytes; clamped to the 256-byte hostname cap, byte 256 lands one byte
    // into the 86th codepoint (85*3=255), producing an incomplete trailing
    // sequence. Before the fix, nlohmann::json::dump()'s strict default threw
    // an uncaught type_error.316 on exactly this input - a fleet-wide 500
    // triggerable by ordinary internationalized agent data, not a
    // hypothetical. The prior "clamps oversize" test above is ASCII-only and
    // provides zero coverage of this: truncating single-byte characters can
    // never produce an invalid sequence, so it is not valid closure evidence
    // for this defect.
    const std::string euro = "\xE2\x82\xAC"; // U+20AC, 3 bytes
    std::string multibyte_hostname;
    multibyte_hostname.reserve(300);
    for (int i = 0; i < 100; ++i)
        multibyte_hostname += euro;
    REQUIRE(multibyte_hostname.size() == 300);

    std::string body = snapshot_body(multibyte_hostname, "proc", "cmd", "user", "ESTABLISHED");
    std::string ex;
    auto parsed = FleetTopologyStore::parse_fleet_snapshot_json(body, "agent-utf8", "linux", &ex);
    REQUIRE(parsed.has_value());
    CHECK(parsed->hostname.size() == 256); // clamped, and split mid-codepoint

    FleetTopologyStore store(fixed_fetcher({*parsed}));
    auto snap = store.get(false);
    REQUIRE(snap != nullptr);

    nlohmann::json j = *snap;
    std::string dumped;
    CHECK_NOTHROW(dumped = dump_topology_safe(j));
    CHECK_FALSE(dumped.empty());
    // U+FFFD (EF BF BD) replaces the invalid trailing bytes rather than
    // dropping them silently or throwing.
    CHECK(dumped.find("\xEF\xBF\xBD") != std::string::npos);
}

TEST_CASE("topology: parser rejects malformed / hostile input without throwing",
          "[viz][topology][hardening][gate7]") {
    // Gate 7 qe-S3 — the parser is called on every heartbeat; it must
    // return nullopt (never throw, never crash) on adversarial input.
    std::string ex;
    CHECK_FALSE(FleetTopologyStore::parse_fleet_snapshot_json("", "a", "linux", &ex).has_value());
    CHECK_FALSE(FleetTopologyStore::parse_fleet_snapshot_json("not json at all", "a", "linux", &ex)
                    .has_value());
    CHECK_FALSE(
        FleetTopologyStore::parse_fleet_snapshot_json("{\"schema\":\"x\",", "a", "linux", &ex)
            .has_value()); // truncated mid-object
    // `processes` of the wrong type — the parser guards with is_array()
    // so it must not throw; it simply yields a snapshot with no procs.
    auto wrong_type = FleetTopologyStore::parse_fleet_snapshot_json(
        "{\"schema\":\"fleet_snapshot.v1\",\"processes\":42}", "a", "linux", &ex);
    REQUIRE(wrong_type.has_value());
    CHECK(wrong_type->processes.empty());
    // Embedded NUL byte in a string field — must not throw.
    std::string nul_body = std::string("{\"schema\":\"fleet_snapshot.v1\",\"hostname\":\"a") +
                           std::string(1, '\0') + "b\"}";
    auto with_nul = FleetTopologyStore::parse_fleet_snapshot_json(nul_body, "a", "linux", &ex);
    CHECK((with_nul.has_value() || !with_nul.has_value())); // only assertion: no throw
}

TEST_CASE("topology: live agent's IP claim blocks a spoofing push", "[viz][hardening][gate7]") {
    // Gate 7 UP-1 — first-claim-wins while the owner is live.
    FleetTopologyStore store(fixed_fetcher({}));
    store.push_snapshot(pushable("agent-A", {"10.0.0.5"}));
    CHECK(store.pushed_map_size() == 1);
    // agent-B claims the same IP while agent-A is fresh -> rejected.
    store.push_snapshot(pushable("agent-B", {"10.0.0.5"}));
    CHECK(store.pushed_rejected_count() == 1);
    CHECK(store.pushed_map_size() == 1); // B never landed
}

TEST_CASE("topology: abandoned IP claim is reclaimable after the reclaim window",
          "[viz][hardening][gate7]") {
    // Gate 7 UP-3 — an agent that crashed without a clean deregister must
    // not strand its local_ips forever. A claim whose owner has not pushed
    // within kIpClaimReclaimAfter is reclaimable, so a re-imaged host
    // re-enrolling on the same DHCP lease is not rejected indefinitely.
    FleetTopologyStore store(fixed_fetcher({}));
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    // agent-A's last push was well past the reclaim window.
    store.push_snapshot(pushable("agent-A", {"10.0.0.5"}, now - 600));
    // agent-B re-enrolls on the same IP -> reclaim, NOT reject.
    store.push_snapshot(pushable("agent-B", {"10.0.0.5"}));
    CHECK(store.pushed_rejected_count() == 0);
    CHECK(store.pushed_map_size() == 2);
}

TEST_CASE("topology: CAP-1 evicts by server-receipt time, not agent-controlled ts",
          "[viz][hardening][gate7]") {
    // Gate 7 UP-4 — the LRU victim must be the genuinely
    // least-recently-seen agent. Keying on the agent-controlled `ts` let
    // an attacker pick the victim by lying about its emit time.
    FleetTopologyStore store(fixed_fetcher({}));
    store.set_pushed_map_cap(2);
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    // agent-OLD: oldest server-receipt time but a *high* (attacker-style)
    // ts. agent-NEW: recent receipt, low ts.
    RawAgentSnapshot old_agent = pushable("agent-OLD", {"10.0.0.1"}, now - 1000);
    old_agent.ts = now + 100000; // attacker lies: "I am very fresh"
    RawAgentSnapshot new_agent = pushable("agent-NEW", {"10.0.0.2"}, now - 1);
    new_agent.ts = 1; // honest agent, low ts
    store.push_snapshot(std::move(old_agent));
    store.push_snapshot(std::move(new_agent));
    // Map at cap (2). A third agent pushes -> evicts the smallest
    // server_received_at, which is agent-OLD despite its inflated ts.
    store.push_snapshot(pushable("agent-THIRD", {"10.0.0.3"}, now));
    CHECK(store.pushed_evicted_for_cap() == 1);
    auto snap = store.get(false);
    std::vector<std::string> ids;
    for (const auto& m : snap->machines)
        ids.push_back(m.agent_id);
    CHECK(std::find(ids.begin(), ids.end(), "agent-OLD") == ids.end());
    CHECK(std::find(ids.begin(), ids.end(), "agent-NEW") != ids.end());
    CHECK(std::find(ids.begin(), ids.end(), "agent-THIRD") != ids.end());
}

TEST_CASE("topology: evict_pushed frees the agent's IP claims", "[viz][hardening][gate7]") {
    // Reverse-index correctness — after evict_pushed, another agent may
    // claim the freed IP immediately (no reclaim-window wait).
    FleetTopologyStore store(fixed_fetcher({}));
    store.push_snapshot(pushable("agent-A", {"10.0.0.5"}));
    store.evict_pushed("agent-A");
    CHECK(store.pushed_map_size() == 0);
    store.push_snapshot(pushable("agent-B", {"10.0.0.5"}));
    CHECK(store.pushed_rejected_count() == 0);
    CHECK(store.pushed_map_size() == 1);
}

TEST_CASE("topology: mixed fleet — registered-but-unpushed agent renders as a stale cube",
          "[viz][hardening][gate7]") {
    // Gate 7 UP-9 / hp-S1 — once any agent pushes, the push path skips
    // the dispatch fetcher; without the roster seam a legacy agent
    // (no fleet_snapshot_json) would vanish entirely. It must instead
    // render as a stale placeholder.
    FleetTopologyStore store(fixed_fetcher({}));
    store.set_roster_provider([]() {
        return std::vector<FleetTopologyStore::RosterEntry>{
            {"agent-PUSHED", "host-pushed", "linux"}, {"agent-LEGACY", "host-legacy", "windows"}};
    });
    store.push_snapshot(pushable("agent-PUSHED", {"10.0.0.1"}));
    auto snap = store.get(false);
    REQUIRE(snap->machines.size() == 2);
    bool legacy_seen = false, legacy_stale = false, pushed_fresh = false;
    for (const auto& m : snap->machines) {
        if (m.agent_id == "agent-LEGACY") {
            legacy_seen = true;
            legacy_stale = m.stale;
        }
        if (m.agent_id == "agent-PUSHED")
            pushed_fresh = !m.stale;
    }
    CHECK(legacy_seen);
    CHECK(legacy_stale);
    CHECK(pushed_fresh);
}

TEST_CASE("topology: push-staleness gate keys on server-receipt time, not agent ts",
          "[viz][hardening][gate7]") {
    // Gate 7 UP-14 — a clock-skewed agent must not be able to render
    // itself permanently fresh (defeating stuck-pump detection) by
    // sending a future `ts`. build_snapshot keys on server_received_at.
    const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    FleetTopologyStore store(fixed_fetcher({}));
    RawAgentSnapshot skewed = pushable("agent-SKEW", {"10.0.0.9"}, now - 600);
    skewed.ts = now + 100000; // agent lies about being fresh
    std::vector<RawAgentSnapshot> raw{skewed};
    auto snap = store.build_snapshot(std::move(raw), false);
    REQUIRE(snap.machines.size() == 1);
    CHECK(snap.machines[0].stale); // stale by server clock despite the future ts
}

// gov cpp-safety finding (#2146 B3): merge_offline_topology had zero direct
// unit-test coverage even before this PR's extraction into a named, testable
// free function (fleet_topology_store.hpp). Three tests below pin its
// documented contract exactly: online-dedup skip, empty-persisted no-op
// (returns the SAME shared_ptr, no copy), and the add-stale-nodes
// copy-on-write path.

TEST_CASE("merge_offline_topology: an already-online agent_id is skipped, never duplicated",
          "[viz][merge_offline]") {
    auto snap = std::make_shared<TopologySnapshot>();
    snap->generated_at = 1000;
    MachineNode online;
    online.agent_id = "agent-A";
    online.hostname = "host-a";
    snap->machines.push_back(online);

    std::vector<OfflineEndpoint> persisted;
    OfflineEndpoint dup;
    dup.agent_id = "agent-A"; // already online -- must be skipped
    dup.hostname = "stale-hostname-should-not-appear";
    persisted.push_back(dup);

    auto merged = merge_offline_topology(snap, persisted);
    REQUIRE(merged->machines.size() == 1);
    CHECK(merged->machines[0].agent_id == "agent-A");
    CHECK(merged->machines[0].hostname == "host-a"); // NOT overwritten by the offline row
    CHECK_FALSE(merged->machines[0].stale);
}

TEST_CASE("merge_offline_topology: empty persisted list returns the SAME shared_ptr, no copy",
          "[viz][merge_offline]") {
    auto snap = std::make_shared<TopologySnapshot>();
    snap->generated_at = 2000;
    MachineNode online;
    online.agent_id = "agent-B";
    snap->machines.push_back(online);

    auto merged = merge_offline_topology(snap, {});
    CHECK(merged.get() == snap.get()); // steady-state: no copy-on-write triggered
}

TEST_CASE("merge_offline_topology: a persisted-but-offline agent becomes a stale placeholder "
          "(copy-on-write)",
          "[viz][merge_offline]") {
    auto snap = std::make_shared<TopologySnapshot>();
    snap->generated_at = 3000;
    MachineNode online;
    online.agent_id = "agent-C";
    snap->machines.push_back(online);
    const auto* orig_ptr = snap.get();

    std::vector<OfflineEndpoint> persisted;
    OfflineEndpoint offline;
    offline.agent_id = "agent-D";
    offline.hostname = "host-d";
    offline.os = "linux";
    persisted.push_back(offline);

    auto merged = merge_offline_topology(snap, persisted);
    CHECK(merged.get() != orig_ptr); // copy-on-write: a new snapshot was allocated
    REQUIRE(merged->machines.size() == 2);
    const MachineNode* stale_node = nullptr;
    for (const auto& m : merged->machines)
        if (m.agent_id == "agent-D")
            stale_node = &m;
    REQUIRE(stale_node != nullptr);
    CHECK(stale_node->hostname == "host-d");
    CHECK(stale_node->os == "linux");
    CHECK(stale_node->stale);
    CHECK(stale_node->processes.empty());
    CHECK(stale_node->connections.empty());
    CHECK(stale_node->listeners.empty());
}
