/**
 * test_fleet_snapshot.cpp -- Unit tests for echo.fleet_snapshot JSON builder
 *
 * Covers shape (schema/ts/hostname/local_ips), redaction propagation,
 * truncation flags, and stability of optional/empty fields. Tests the
 * pure free function build_fleet_snapshot_json -- the plugin wiring is
 * exercised end-to-end by the integration UAT.
 */

#include "echo_collectors.hpp"
#include "echo_fleet_snapshot.hpp"

#include <yuzu/agent/process_enum.hpp>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using yuzu::agent::ProcessInfo;
using yuzu::echo::build_fleet_snapshot_json;
using yuzu::echo::kFleetSnapshotMaxRows;
using yuzu::echo::NetConnection;
using json = nlohmann::json;

namespace {

ProcessInfo make_proc(uint32_t pid, uint32_t ppid, std::string name, std::string cmdline,
                      std::string user) {
    ProcessInfo p;
    p.pid = pid;
    p.ppid = ppid;
    p.name = std::move(name);
    p.cmdline = std::move(cmdline);
    p.user = std::move(user);
    return p;
}

NetConnection make_conn(std::string proto, std::string local_addr, int local_port,
                        std::string remote_addr, int remote_port, std::string state, uint32_t pid,
                        std::string process_name) {
    NetConnection c;
    c.proto = std::move(proto);
    c.local_addr = std::move(local_addr);
    c.local_port = local_port;
    c.remote_addr = std::move(remote_addr);
    c.remote_port = remote_port;
    c.state = std::move(state);
    c.pid = pid;
    c.process_name = std::move(process_name);
    return c;
}

} // namespace

TEST_CASE("fleet_snapshot: empty inputs produce a valid envelope", "[echo][fleet]") {
    auto out = build_fleet_snapshot_json({}, {}, {}, "host-1", 1715299200);
    auto j = json::parse(out);

    CHECK(j["schema"] == "fleet_snapshot.v1");
    CHECK(j["ts"] == 1715299200);
    CHECK(j["hostname"] == "host-1");
    CHECK(j["local_ips"].is_array());
    CHECK(j["local_ips"].empty());
    CHECK(j["processes"].is_array());
    CHECK(j["processes"].empty());
    CHECK(j["connections"].is_array());
    CHECK(j["connections"].empty());
    CHECK(j["truncated_processes"] == false);
    CHECK(j["truncated_connections"] == false);
}

TEST_CASE("fleet_snapshot: processes round-trip", "[echo][fleet]") {
    std::vector<ProcessInfo> procs = {
        make_proc(1, 0, "init", "/sbin/init", "root"),
        make_proc(42, 1, "firefox", "firefox --new-tab", "alice"),
    };
    auto out = build_fleet_snapshot_json(procs, {}, {}, "h", 1, {});
    auto j = json::parse(out);

    REQUIRE(j["processes"].size() == 2);
    CHECK(j["processes"][0]["pid"] == 1);
    CHECK(j["processes"][0]["ppid"] == 0);
    CHECK(j["processes"][0]["name"] == "init");
    CHECK(j["processes"][0]["cmdline"] == "/sbin/init");
    CHECK(j["processes"][0]["user"] == "root");
    CHECK(j["processes"][1]["pid"] == 42);
    CHECK(j["processes"][1]["name"] == "firefox");
    CHECK(j["processes"][1]["cmdline"] == "firefox --new-tab");
}

TEST_CASE("fleet_snapshot: connections round-trip", "[echo][fleet]") {
    auto c1 =
        make_conn("tcp", "10.0.0.7", 5432, "10.0.0.42", 54321, "ESTABLISHED", 100, "postgres");
    c1.remote_host = "db.internal";
    std::vector<NetConnection> conns = {
        c1,
        make_conn("tcp", "127.0.0.1", 8080, "127.0.0.1", 41234, "ESTABLISHED", 200, "nginx"),
    };
    auto out = build_fleet_snapshot_json({}, conns, {}, "h", 1);
    auto j = json::parse(out);

    REQUIRE(j["connections"].size() == 2);
    CHECK(j["connections"][0]["proto"] == "tcp");
    CHECK(j["connections"][0]["local_addr"] == "10.0.0.7");
    CHECK(j["connections"][0]["local_port"] == 5432);
    CHECK(j["connections"][0]["remote_addr"] == "10.0.0.42");
    CHECK(j["connections"][0]["remote_host"] == "db.internal"); // QE-S2
    CHECK(j["connections"][0]["remote_port"] == 54321);
    CHECK(j["connections"][0]["state"] == "ESTABLISHED");
    CHECK(j["connections"][0]["pid"] == 100);
    CHECK(j["connections"][0]["process_name"] == "postgres");
    // remote_host must be present even when empty (default from make_conn)
    CHECK(j["connections"][1]["remote_host"] == "");
}

TEST_CASE("fleet_snapshot: source_paused markers emitted when sources disabled", "[echo][fleet]") {
    // plugin-B1 / compliance-F1 fix: paused process or tcp source must not
    // silently leak data; the snapshot carries explicit markers.
    auto out = build_fleet_snapshot_json({}, {}, {}, "h", 1, {},
                                         /*process_source_enabled=*/false,
                                         /*tcp_source_enabled=*/false);
    auto j = json::parse(out);
    CHECK(j["process_source_paused"] == true);
    CHECK(j["tcp_source_paused"] == true);
    CHECK(j["schema_minor"] == 2);
}

TEST_CASE("fleet_snapshot: schema_minor present in envelope", "[echo][fleet]") {
    auto out = build_fleet_snapshot_json({}, {}, {}, "h", 1);
    auto j = json::parse(out);
    CHECK(j["schema_minor"] == 2);
    // markers omitted when sources are enabled (default)
    CHECK(!j.contains("process_source_paused"));
    CHECK(!j.contains("tcp_source_paused"));
}

TEST_CASE("merge_live_and_recent_connections: recent-only rows survive with computed age",
          "[echo][fleet][merge]") {
    // A connection observed in Echo's tcp_live 30 minutes ago that isn't
    // currently in /proc/net/tcp must still appear in the merged output,
    // with last_seen_seconds_ago = now_ts - recent.ts.
    using yuzu::echo::merge_live_and_recent_connections;
    using yuzu::echo::NetworkEvent;
    yuzu::echo::NetworkEvent recent;
    recent.ts = 4000;
    recent.proto = "tcp";
    recent.local_addr = "10.0.0.10";
    recent.local_port = 50001;
    recent.remote_addr = "10.0.0.20";
    recent.remote_port = 5432;
    recent.state = "ESTABLISHED";
    recent.pid = 100;
    recent.process_name = "node";

    auto merged = merge_live_and_recent_connections(
        /*live=*/{}, /*recent=*/{recent}, /*now_ts=*/5800);
    REQUIRE(merged.size() == 1);
    CHECK(merged[0].proto == "tcp");
    CHECK(merged[0].local_port == 50001);
    CHECK(merged[0].last_seen_seconds_ago == 1800);
}

TEST_CASE("merge_live_and_recent_connections: live row preempts a same-5-tuple recent row",
          "[echo][fleet][merge]") {
    // /proc shows the connection right now, and tcp_live remembers an
    // earlier observation of the same 5-tuple+pid. The live row wins —
    // it's the most authoritative current state.
    using yuzu::echo::merge_live_and_recent_connections;
    auto live = make_conn("tcp", "10.0.0.10", 50001, "10.0.0.20", 5432, "ESTABLISHED", 100, "node");
    yuzu::echo::NetworkEvent recent;
    recent.ts = 4000;
    recent.proto = "tcp";
    recent.local_addr = "10.0.0.10";
    recent.local_port = 50001;
    recent.remote_addr = "10.0.0.20";
    recent.remote_port = 5432;
    recent.state = "ESTABLISHED";
    recent.pid = 100;
    recent.process_name = "node";

    auto merged = merge_live_and_recent_connections({live}, {recent}, /*now_ts=*/5800);
    REQUIRE(merged.size() == 1);
    CHECK(merged[0].last_seen_seconds_ago == 0); // live row, not historical
}

TEST_CASE("merge_live_and_recent_connections: distinct 5-tuples coexist", "[echo][fleet][merge]") {
    using yuzu::echo::merge_live_and_recent_connections;
    auto live = make_conn("tcp", "10.0.0.10", 50001, "10.0.0.20", 5432, "ESTABLISHED", 100, "node");
    yuzu::echo::NetworkEvent recent;
    recent.ts = 4000;
    recent.proto = "tcp";
    recent.local_addr = "10.0.0.10";
    recent.local_port = 60001; // different local port → different 5-tuple
    recent.remote_addr = "10.0.0.30";
    recent.remote_port = 6379;
    recent.state = "ESTABLISHED";
    recent.pid = 100;
    recent.process_name = "node";

    auto merged = merge_live_and_recent_connections({live}, {recent}, /*now_ts=*/5800);
    REQUIRE(merged.size() == 2);
    // Live first (zero age), then recent.
    CHECK(merged[0].last_seen_seconds_ago == 0);
    CHECK(merged[1].last_seen_seconds_ago == 1800);
    CHECK(merged[1].remote_port == 6379);
}

TEST_CASE("fleet_snapshot: last_seen_seconds_ago round-trips for historical connections",
          "[echo][fleet][recent]") {
    // PR 9-pre / Slice 2 follow-up: Echo widens fleet_snapshot from "currently
    // ESTABLISHED" to "ESTABLISHED within the last hour" by joining /proc
    // (live) with tcp_live (recent). Each connection carries its age so the
    // server can later distinguish live tubes from recently-recent ones.
    //
    // Wire contract: `last_seen_seconds_ago` is OMITTED when zero (live)
    // and EMITTED otherwise (additive, schema_minor 1->2).
    auto live =
        make_conn("tcp", "10.0.0.7", 5432, "10.0.0.42", 54321, "ESTABLISHED", 100, "postgres");
    auto recent =
        make_conn("tcp", "10.0.0.7", 6379, "10.0.0.99", 6379, "ESTABLISHED", 101, "redis-cli");
    recent.last_seen_seconds_ago = 1800; // 30 minutes ago

    std::vector<NetConnection> conns = {live, recent};
    auto out = build_fleet_snapshot_json({}, conns, {}, "h", 1);
    auto j = json::parse(out);

    REQUIRE(j["connections"].size() == 2);
    // Live row: field omitted.
    CHECK(!j["connections"][0].contains("last_seen_seconds_ago"));
    // Recent row: field present with the exact value.
    REQUIRE(j["connections"][1].contains("last_seen_seconds_ago"));
    CHECK(j["connections"][1]["last_seen_seconds_ago"] == 1800);
    // Schema bumped to advertise the additive field.
    CHECK(j["schema_minor"] == 2);
}

TEST_CASE("fleet_snapshot: cmdline redaction applied", "[echo][fleet][redaction]") {
    std::vector<ProcessInfo> procs = {
        make_proc(1, 0, "myapp", "myapp --password=hunter2", "alice"),
        make_proc(2, 0, "noisy", "noisy --regular-flag", "bob"),
    };
    auto out = build_fleet_snapshot_json(procs, {}, {}, "h", 1, {"*password*"});
    auto j = json::parse(out);

    CHECK(j["processes"][0]["cmdline"] == "[REDACTED by Echo]");
    CHECK(j["processes"][1]["cmdline"] == "noisy --regular-flag");
}

TEST_CASE("fleet_snapshot: default redaction patterns redact secrets", "[echo][fleet][redaction]") {
    std::vector<ProcessInfo> procs = {
        make_proc(1, 0, "a", "a --token=abc123", "u"),
        make_proc(2, 0, "b", "b --api_key=xyz", "u"),
        make_proc(3, 0, "c", "c --ordinary --flag", "u"),
    };
    // Use the implicit default redaction_patterns (token/api_key/etc.)
    auto out = build_fleet_snapshot_json(procs, {}, {}, "h", 1);
    auto j = json::parse(out);

    CHECK(j["processes"][0]["cmdline"] == "[REDACTED by Echo]");
    CHECK(j["processes"][1]["cmdline"] == "[REDACTED by Echo]");
    CHECK(j["processes"][2]["cmdline"] == "c --ordinary --flag");
}

TEST_CASE("fleet_snapshot: process truncation sets flag and caps array",
          "[echo][fleet][truncation]") {
    std::vector<ProcessInfo> procs;
    for (int i = 0; i < 5; ++i)
        procs.push_back(make_proc(static_cast<uint32_t>(i), 0, "p" + std::to_string(i), "", "u"));
    auto out = build_fleet_snapshot_json(procs, {}, {}, "h", 1, {}, true, true, /*max_rows=*/2);
    auto j = json::parse(out);

    CHECK(j["processes"].size() == 2);
    CHECK(j["truncated_processes"] == true);
    CHECK(j["truncated_connections"] == false);
}

TEST_CASE("fleet_snapshot: connection truncation sets flag and caps array",
          "[echo][fleet][truncation]") {
    std::vector<NetConnection> conns;
    for (int i = 0; i < 5; ++i)
        conns.push_back(make_conn("tcp", "10.0.0.1", 1000 + i, "10.0.0.2", 80, "EST", 1, "p"));
    auto out = build_fleet_snapshot_json({}, conns, {}, "h", 1, {}, true, true, /*max_rows=*/3);
    auto j = json::parse(out);

    CHECK(j["connections"].size() == 3);
    CHECK(j["truncated_connections"] == true);
    CHECK(j["truncated_processes"] == false);
}

TEST_CASE("fleet_snapshot: max_rows<=0 falls back to default", "[echo][fleet][truncation]") {
    std::vector<ProcessInfo> procs;
    for (int i = 0; i < 10; ++i)
        procs.push_back(make_proc(static_cast<uint32_t>(i), 0, "p", "", "u"));
    auto out = build_fleet_snapshot_json(procs, {}, {}, "h", 1, {}, true, true, /*max_rows=*/0);
    auto j = json::parse(out);
    // 10 < kFleetSnapshotMaxRows so all kept and not truncated
    CHECK(j["processes"].size() == 10);
    CHECK(j["truncated_processes"] == false);
}

TEST_CASE("fleet_snapshot: local_ips passed through verbatim", "[echo][fleet]") {
    std::vector<std::string> ips = {"10.0.0.7", "192.168.1.5", "fd00::1"};
    auto out = build_fleet_snapshot_json({}, {}, ips, "h", 1);
    auto j = json::parse(out);

    REQUIRE(j["local_ips"].size() == 3);
    CHECK(j["local_ips"][0] == "10.0.0.7");
    CHECK(j["local_ips"][1] == "192.168.1.5");
    CHECK(j["local_ips"][2] == "fd00::1");
}

TEST_CASE("fleet_snapshot: payload bound at full cap", "[echo][fleet][size]") {
    // Worst-realistic case at the cap: kFleetSnapshotMaxRows procs + conns
    // with average-length names/cmdlines. JSON verbosity puts this around
    // ~1.3 MB; we assert <2 MB so the server can size receive buffers.
    // Realistic hosts at idle/normal load emit 50-500 KB.
    std::vector<ProcessInfo> procs;
    procs.reserve(kFleetSnapshotMaxRows);
    for (int i = 0; i < kFleetSnapshotMaxRows; ++i) {
        procs.push_back(
            make_proc(static_cast<uint32_t>(i + 1), 1, "process_name_" + std::to_string(i),
                      "/usr/bin/binary --some-flag --another " + std::to_string(i), "userN"));
    }
    std::vector<NetConnection> conns;
    conns.reserve(kFleetSnapshotMaxRows);
    for (int i = 0; i < kFleetSnapshotMaxRows; ++i) {
        conns.push_back(make_conn("tcp", "10.0.0.7", 30000 + (i % 10000), "10.0.0.42",
                                  80 + (i % 1024), "ESTABLISHED", 1, "process_name_x"));
    }
    auto out = build_fleet_snapshot_json(procs, conns, {"10.0.0.7"}, "host-1", 1);
    CHECK(out.size() < 2 * 1024 * 1024);
    CHECK(json::parse(out)["schema"] == "fleet_snapshot.v1");
}
