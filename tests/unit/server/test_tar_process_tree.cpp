/// @file test_tar_process_tree.cpp
/// Unit tests for the TAR process-tree reconstruction engine (tar_process_tree.*):
/// the __schema__ parsers, point-in-time/window reconstruction, pid-reuse,
/// orphan→root, the suspicious parent→child anomaly, anomalies-only pruning, the
/// timescale anchors + window resolution, and render HTML-escaping. Pure — no store,
/// no network.

#include "tar_process_tree.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

TarProcEvent ev(std::int64_t ts, const char* action, std::uint32_t pid, std::uint32_t ppid,
                const char* name, const char* user = "", const char* cmd = "") {
    TarProcEvent e;
    e.ts = ts;
    e.action = action;
    e.pid = pid;
    e.ppid = ppid;
    e.name = name;
    e.user = user;
    e.cmdline = cmd;
    return e;
}

// First node with `pid`; nullptr if absent. `running_pref` picks a running
// incarnation when a pid has several.
const TarProcNode* find_pid(const TarProcTree& t, std::uint32_t pid, bool running_pref = false) {
    const TarProcNode* any = nullptr;
    for (const auto& n : t.nodes) {
        if (n.pid != pid)
            continue;
        if (!any)
            any = &n;
        if (running_pref && n.running)
            return &n;
    }
    return any;
}

int count_pid(const TarProcTree& t, std::uint32_t pid) {
    int c = 0;
    for (const auto& n : t.nodes)
        if (n.pid == pid)
            ++c;
    return c;
}

} // namespace

TEST_CASE("tar parse: process __schema__ output", "[tar][tree][parse]") {
    const std::string out =
        "__schema__|ts|action|pid|ppid|name|cmdline|user\n"
        "100|started|1|0|systemd||root\n"
        "110|started|100|1|bash||alice\n"
        "total|2\n"; // trailer row — too few cells, must be skipped
    auto events = parse_tar_process_output(out);
    REQUIRE(events.size() == 2);
    CHECK(events[0].ts == 100);
    CHECK(events[0].pid == 1);
    CHECK(events[0].ppid == 0);
    CHECK(events[0].name == "systemd");
    CHECK(events[0].action == "started");
    CHECK(events[1].pid == 100);
    CHECK(events[1].user == "alice");
}

TEST_CASE("tar parse: error payload and wrong shape yield empty", "[tar][tree][parse]") {
    CHECK(parse_tar_process_output("error|database is locked\n").empty());
    // Missing the required `pid` column → refuse rather than guess.
    CHECK(parse_tar_process_output("__schema__|ts|action|ppid|name\n100|started|0|x\n").empty());
}

TEST_CASE("tar parse: tcp __schema__ output", "[tar][tree][parse]") {
    const std::string out =
        "__schema__|pid|process_name|proto|local_port|remote_addr|remote_port|state|ts|action\n"
        "100|bash|tcp|54321|1.2.3.4|443|ESTABLISHED|160|connected\n";
    auto conns = parse_tar_tcp_output(out);
    REQUIRE(conns.size() == 1);
    CHECK(conns[0].pid == 100);
    CHECK(conns[0].remote_addr == "1.2.3.4");
    CHECK(conns[0].remote_port == 443);
    CHECK(conns[0].state == "ESTABLISHED");
}

TEST_CASE("tar tree: basic parent/child reconstruction", "[tar][tree]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(110, "started", 100, 1, "bash", "alice"),
        ev(120, "started", 200, 100, "python", "alice"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    REQUIRE(t.roots.size() == 1);
    const TarProcNode& root = t.nodes[t.roots[0]];
    CHECK(root.pid == 1);
    REQUIRE(root.children.size() == 1);
    const TarProcNode& bash = t.nodes[root.children[0]];
    CHECK(bash.pid == 100);
    REQUIRE(bash.children.size() == 1);
    CHECK(t.nodes[bash.children[0]].pid == 200);
    CHECK(t.running_count == 3);
    CHECK(t.exited_count == 0);
}

TEST_CASE("tar tree: window overlap includes exited-in-window, excludes exited-before",
          "[tar][tree][window]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(100, "started", 60, 1, "early"),
        ev(120, "stopped", 60, 1, "early"), // exited 120 — before `from`
        ev(150, "started", 50, 1, "recent"),
        ev(160, "stopped", 50, 1, "recent"), // exited 160 — within window
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, /*from=*/155, /*to=*/2000, a);
    CHECK(find_pid(t, 60) == nullptr);          // exited before the window
    const TarProcNode* recent = find_pid(t, 50);
    REQUIRE(recent != nullptr);                 // exited inside the window → shown
    CHECK_FALSE(recent->running);
    CHECK(recent->exited_ts == 160);
    CHECK(find_pid(t, 1) != nullptr);           // long-running → always present
}

TEST_CASE("tar tree: long-running started before window still appears (running)",
          "[tar][tree][window]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(100, "started", 500, 1, "longproc"), // started long ago, never stops
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, /*from=*/1000, /*to=*/2000, a);
    const TarProcNode* lp = find_pid(t, 500);
    REQUIRE(lp != nullptr);
    CHECK(lp->running);
}

TEST_CASE("tar tree: to excludes later starts (point-in-time upper bound)", "[tar][tree][window]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(300, "started", 77, 1, "future"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, /*from=*/0, /*to=*/200, a);
    CHECK(find_pid(t, 77) == nullptr);
    CHECK(find_pid(t, 1) != nullptr);
}

TEST_CASE("tar tree: pid reuse yields two incarnations", "[tar][tree][reuse]") {
    std::vector<TarProcEvent> e{
        ev(50, "started", 1, 0, "systemd"),
        ev(100, "started", 100, 1, "bash"),
        ev(150, "stopped", 100, 1, "bash"),
        ev(200, "started", 100, 1, "powershell.exe"), // pid reused, still running
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    CHECK(count_pid(t, 100) == 2);
    const TarProcNode* run = find_pid(t, 100, /*running_pref=*/true);
    REQUIRE(run != nullptr);
    CHECK(run->running);
    CHECK(run->name == "powershell.exe");
    // Both incarnations parent to the single pid-1 root.
    const TarProcNode& root = t.nodes[t.roots[0]];
    CHECK(root.children.size() == 2);
}

TEST_CASE("tar tree: orphan whose parent is absent becomes a root", "[tar][tree]") {
    std::vector<TarProcEvent> e{ev(100, "started", 500, 400, "orphan")}; // ppid 400 absent
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    REQUIRE(t.roots.size() == 1);
    CHECK(t.nodes[t.roots[0]].pid == 500);
}

TEST_CASE("tar anomaly: suspicious parent->child flagged, benign parent not", "[tar][tree][anomaly]") {
    std::string evidence;
    CHECK(tar_is_suspicious_spawn("winword.exe", "powershell.exe", &evidence));
    CHECK(evidence.find("winword.exe") != std::string::npos);
    CHECK_FALSE(tar_is_suspicious_spawn("explorer.exe", "cmd.exe")); // benign — explorer excluded
    CHECK_FALSE(tar_is_suspicious_spawn("bash", "ls"));

    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(110, "started", 10, 1, "winword.exe", "bob"),
        ev(120, "started", 20, 10, "powershell.exe", "bob"),
        ev(130, "started", 40, 1, "explorer.exe"),
        ev(140, "started", 50, 40, "cmd.exe"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    const TarProcNode* ps = find_pid(t, 20);
    REQUIRE(ps != nullptr);
    CHECK(ps->anomaly);
    const TarProcNode* benign = find_pid(t, 50);
    REQUIRE(benign != nullptr);
    CHECK_FALSE(benign->anomaly);
    CHECK(t.anomaly_count == 1);
}

TEST_CASE("tar tree: full tree is never pruned (filtering is client-side)", "[tar][tree][anomaly]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(110, "started", 10, 1, "winword.exe"),
        ev(120, "started", 20, 10, "powershell.exe"), // the anomaly
        ev(130, "started", 30, 1, "sshd"),
        ev(140, "started", 40, 30, "bash"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    // Reconstruction keeps EVERY node (running/exited/anomalies filtering is a
    // client-side display concern); the flag is set but the tree is not pruned.
    CHECK(t.running_count == 5);
    CHECK(t.anomaly_count == 1);
    REQUIRE(t.roots.size() == 1);
    const TarProcNode& root = t.nodes[t.roots[0]];
    REQUIRE(root.children.size() == 2);          // BOTH winword and sshd remain
    CHECK(find_pid(t, 40) != nullptr);           // bash under sshd still present
}

TEST_CASE("tar render: rows carry data-state and data-anom for client filters",
          "[tar][tree][render]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(110, "started", 10, 1, "winword.exe"),
        ev(120, "started", 20, 10, "powershell.exe"), // anomaly, running
        ev(130, "started", 50, 1, "old"),
        ev(140, "stopped", 50, 1, "old"),             // exited
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "dev1", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find("data-state=\"running\"") != std::string::npos);
    CHECK(html.find("data-state=\"exited\"") != std::string::npos);
    CHECK(html.find("data-anom=\"1\"") != std::string::npos); // powershell flagged
}

TEST_CASE("tar render: inline network summary shows remote IP:port", "[tar][tree][render][net]") {
    std::vector<TarProcEvent> e{ev(100, "started", 1234, 1, "curl")};
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    std::vector<TarTcpConn> conns;
    TarTcpConn c;
    c.pid = 1234;
    c.proto = "tcp";
    c.remote_addr = "203.0.113.7"; // public
    c.remote_port = 443;
    c.local_port = 51000;
    c.state = "ESTABLISHED";
    conns.push_back(c);
    auto html = render_tar_tree_fragment(t, conns, "dev1", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find("203.0.113.7:443") != std::string::npos); // IP:port surfaced inline
    CHECK(html.find("tt-net") != std::string::npos);
    CHECK(html.find("tt-ep-pub") != std::string::npos);        // public endpoint highlighted
}

TEST_CASE("tar render: same-name siblings group past the threshold", "[tar][tree][render]") {
    std::vector<TarProcEvent> e{ev(100, "started", 1, 0, "services.exe")};
    for (std::uint32_t p = 2000; p < 2005; ++p) // 5 svchost.exe under services.exe
        e.push_back(ev(110, "started", p, 1, "svchost.exe"));
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "dev1", "0123456789abcdef0123456789abcdef", "windows");
    CHECK(html.find("tar-tree-group") != std::string::npos);
    CHECK(html.find("\xC3\x97" "5") != std::string::npos); // "×5" group count
}

TEST_CASE("tar render: few same-name siblings are not grouped", "[tar][tree][render]") {
    std::vector<TarProcEvent> e{ev(100, "started", 1, 0, "services.exe"),
                                ev(110, "started", 2000, 1, "svchost.exe"),
                                ev(110, "started", 2001, 1, "svchost.exe")}; // only 2
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "dev1", "0123456789abcdef0123456789abcdef", "windows");
    CHECK(html.find("tar-tree-group") == std::string::npos);
}

TEST_CASE("tar render: grouping threshold boundary (3 no, 4 yes)", "[tar][tree][render]") {
    auto build = [](std::uint32_t count) {
        std::vector<TarProcEvent> e{ev(100, "started", 1, 0, "services.exe")};
        for (std::uint32_t i = 0; i < count; ++i)
            e.push_back(ev(110, "started", 2000 + i, 1, "svchost.exe"));
        auto a = compute_tar_anchors(e);
        auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
        return render_tar_tree_fragment(t, {}, "d", "0123456789abcdef0123456789abcdef", "windows");
    };
    CHECK(build(3).find("tar-tree-group") == std::string::npos); // exactly 3 → no group
    CHECK(build(4).find("tar-tree-group") != std::string::npos);  // exactly 4 → group
}

// ── Hardening-round coverage (governance Gate 3/4) ──────────────────────────

TEST_CASE("tar parse_ts_param: epoch, datetime-local, and rejection", "[tar][tree][parse]") {
    CHECK(parse_ts_param("") == 0);
    CHECK(parse_ts_param("1718000000") == 1718000000);
    CHECK(parse_ts_param("2026-06-18T12:00:00") == 1781784000); // verified UTC epoch
    CHECK(parse_ts_param("2026-06-18T12:00") == parse_ts_param("2026-06-18T12:00:00")); // seconds optional
    CHECK(parse_ts_param("9999999999999999999") == 0); // 19 digits → overflow-guarded to 0
    CHECK(parse_ts_param("2026-13-01T00:00") == 0);     // invalid month
    CHECK(parse_ts_param("99999-01-01T00:00") == 0);    // year out of [1970,9999]
    CHECK(parse_ts_param("not-a-time") == 0);
    // Pin the exact sscanf("%d-%d-%dT%d:%d:%d", n >= 5) semantics the strtol
    // rewrite preserves (glibc __isoc23_sscanf removal):
    CHECK(parse_ts_param(" 2026-06-18T12:00:00") == 1781784000); // %d-style leading whitespace
    CHECK(parse_ts_param("2026-06-18T12:00:") == 1781784000);    // bare trailing ':' → Se stays 0
    CHECK(parse_ts_param("2026-06-18T12:00:30xyz") == 1781784030); // trailing junk ignored
    CHECK(parse_ts_param("2026-06-18 12:00:00") == 0);           // space instead of 'T' rejected
    CHECK(parse_ts_param("2026-06-18T12-00") == 0);              // wrong time delimiter rejected
    CHECK(parse_ts_param("2026-+6-+18T+12:+00:+30") == 1781784030); // %d-style sign acceptance
    CHECK(parse_ts_param("2026-06-18T12:00:30.123") == 1781784030); // fractional suffix ignored
}

TEST_CASE("tar anchors: non-positive ts cannot poison observed_since", "[tar][tree][anchor]") {
    std::vector<TarProcEvent> e{ev(0, "started", 9, 0, "garbage"),     // ts<=0 ignored
                                ev(-5, "started", 8, 0, "garbage"),    // negative ignored
                                ev(1000, "started", 1, 0, "systemd")};
    auto a = compute_tar_anchors(e);
    CHECK(a.observed_since == 1000);
    CHECK(a.install_ts == 1000);
}

TEST_CASE("tar anchors: boot falls back to install when no root start", "[tar][tree][anchor]") {
    std::vector<TarProcEvent> e{ev(500, "started", 100, 50, "bash")}; // no ppid==0 start
    auto a = compute_tar_anchors(e);
    CHECK(a.observed_since == 500);
    CHECK(a.boot_ts == a.install_ts); // fallback
}

TEST_CASE("tar tree: stop-without-start synthesises a start_known=false incarnation",
          "[tar][tree]") {
    // Only the stop survives (the start aged out of the cap). Window covers the stop.
    std::vector<TarProcEvent> e{ev(200, "stopped", 777, 1, "ghost", "alice")};
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    const TarProcNode* n = find_pid(t, 777);
    REQUIRE(n != nullptr);
    CHECK_FALSE(n->start_known);
    CHECK_FALSE(n->running);
    CHECK(n->exited_ts == 200);
    CHECK(n->name == "ghost");
}

TEST_CASE("tar anomaly: denylist is basename-stripped and case-insensitive", "[tar][tree][anomaly]") {
    CHECK(tar_is_suspicious_spawn("C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                                  "POWERSHELL.EXE"));
    CHECK(tar_is_suspicious_spawn("/opt/MsEdge/msedge.exe", "Cmd.Exe"));
    CHECK_FALSE(tar_is_suspicious_spawn("notepad.exe", "powershell.exe")); // benign parent
}

TEST_CASE("tar tree: parent resolution prefers the containing incarnation", "[tar][tree][reuse]") {
    // ppid 10 has an exited incarnation [100,150] and a running one [180,..]; a child
    // starting at 200 must link to the RUNNING (containing) incarnation, not the exited.
    std::vector<TarProcEvent> e{
        ev(100, "started", 10, 1, "parent"),
        ev(150, "stopped", 10, 1, "parent"),
        ev(180, "started", 10, 1, "parent"), // reused, running, contains 200
        ev(200, "started", 50, 10, "child"),
        ev(90, "started", 1, 0, "systemd"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    const TarProcNode* child = find_pid(t, 50);
    REQUIRE(child != nullptr);
    REQUIRE(child->parent != TarProcNode::kNoParent);
    const TarProcNode& par = t.nodes[child->parent];
    CHECK(par.pid == 10);
    CHECK(par.running);          // the containing (live) incarnation
    CHECK(par.started_ts == 180);
}

TEST_CASE("tar tree: cycle guard leaves a reused-pid loop node as a root", "[tar][tree][reuse]") {
    // A forged stream where 10's parent is 20 and 20's parent is 10 (a loop). The guard
    // must break it — every node still renders, none infinitely recurses.
    std::vector<TarProcEvent> e{ev(100, "started", 10, 20, "a"),
                                ev(100, "started", 20, 10, "b")};
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    REQUIRE_FALSE(t.roots.empty());      // not all nodes are children of each other
    CHECK(t.running_count == 2);          // both reachable, counted once
}

TEST_CASE("tar tree: node cap sets truncated", "[tar][tree][cap]") {
    std::vector<TarProcEvent> e;
    e.reserve(kTarTreeMaxNodes + 2);
    for (std::uint32_t i = 0; i < kTarTreeMaxNodes + 1; ++i)
        e.push_back(ev(100 + i, "started", 1000 + i, 0, "p")); // all running roots
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 0x7fffffffLL, a);
    CHECK(t.truncated);
    CHECK(t.running_count == static_cast<int>(kTarTreeMaxNodes)); // capped, running kept
}

TEST_CASE("tar render: net_cell dedups, orders public first, labels listeners",
          "[tar][tree][render][net]") {
    std::vector<TarProcEvent> e{ev(100, "started", 42, 1, "proc")};
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto conn = [](const char* raddr, int rport, int lport, const char* state) {
        TarTcpConn c; c.pid = 42; c.proto = "tcp"; c.remote_addr = raddr;
        c.remote_port = rport; c.local_port = lport; c.state = state; return c;
    };
    std::vector<TarTcpConn> conns{
        conn("203.0.113.9", 443, 5001, "ESTABLISHED"),// public (sorts first, shown inline)
        conn("203.0.113.9", 443, 5001, "ESTABLISHED"),// duplicate → deduped
        conn("", 0, 8080, "LISTEN"),                  // listener (2nd distinct, shown inline)
    };
    auto html = render_tar_tree_fragment(t, conns, "d", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find(":8080 listen") != std::string::npos);  // listener label
    CHECK(html.find("203.0.113.9:443") != std::string::npos);
    CHECK(html.find("tt-ep-pub") != std::string::npos);      // public endpoint highlighted
    // 2 distinct endpoints (one dup removed): badge count "2" appears in the net cell.
    CHECK(html.find("tt-net-ico\">\xE2\x86\x97</span>2") != std::string::npos);
}

TEST_CASE("tar anchors: install = min ts, boot = latest root start", "[tar][tree][anchor]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "systemd"),
        ev(500, "started", 1, 0, "systemd"), // reboot — newer ppid==0 start
        ev(600, "started", 100, 1, "bash"),
    };
    auto a = compute_tar_anchors(e);
    CHECK(a.observed_since == 100);
    CHECK(a.install_ts == 100);
    CHECK(a.boot_ts == 500);
}

TEST_CASE("tar window: preset resolution", "[tar][tree][window]") {
    TarTreeAnchors a;
    a.observed_since = 100;
    a.install_ts = 100;
    a.boot_ts = 500;
    const std::int64_t now = 10000;

    CHECK(resolve_tar_window("1m", 0, 0, a, now).from_ts == now - 60);
    CHECK(resolve_tar_window("10m", 0, 0, a, now).from_ts == now - 600);
    CHECK(resolve_tar_window("1h", 0, 0, a, now).from_ts == now - 3600);
    CHECK(resolve_tar_window("1d", 0, 0, a, now).from_ts == 0); // now-86400 < 0 → clamped
    CHECK(resolve_tar_window("on_install", 0, 0, a, now).from_ts == 100);
    CHECK(resolve_tar_window("on_boot", 0, 0, a, now).from_ts == 500);
    CHECK(resolve_tar_window("garbage", 0, 0, a, now).from_ts == now - 600); // default 10m

    auto custom = resolve_tar_window("custom", 2000, 3000, a, now);
    CHECK(custom.from_ts == 2000);
    CHECK(custom.to_ts == 3000);
    auto blank = resolve_tar_window("custom", 0, 0, a, now);
    CHECK(blank.from_ts == 100);   // unset from → install
    CHECK(blank.to_ts == now);     // unset to → now
    auto reversed = resolve_tar_window("custom", 5000, 4000, a, now);
    CHECK(reversed.to_ts == reversed.from_ts); // reversed range collapses to a point
}

TEST_CASE("tar render: agent-controlled fields are HTML-escaped", "[tar][tree][render]") {
    std::vector<TarProcEvent> e{
        ev(100, "started", 1, 0, "<script>evil</script>", "us\"er"),
    };
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "dev1", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find("<script>evil") == std::string::npos);
    CHECK(html.find("&lt;script&gt;evil") != std::string::npos);

    auto detail = render_tar_proc_detail(t.nodes[0], {}, "linux");
    CHECK(detail.find("<script>evil") == std::string::npos);
    CHECK(detail.find("&lt;script&gt;") != std::string::npos);
}

TEST_CASE("tar render: Windows names-only caption, Linux shows cmdline", "[tar][tree][render]") {
    TarProcNode n;
    n.pid = 42;
    n.ppid = 1;
    n.name = "proc";
    n.cmdline = "/usr/bin/proc --flag";
    n.running = true;
    n.start_known = true;
    n.started_ts = 100;

    auto win = render_tar_proc_detail(n, {}, "windows");
    CHECK(win.find("names-only on Windows") != std::string::npos);
    CHECK(win.find("/usr/bin/proc") == std::string::npos); // not surfaced on Windows

    auto lin = render_tar_proc_detail(n, {}, "linux");
    CHECK(lin.find("/usr/bin/proc --flag") != std::string::npos);
}

// ── Review-round coverage (PR #1551 should-fix cluster) ─────────────────────

TEST_CASE("tar render: interleaved same-name siblings group by first appearance",
          "[tar][tree][render]") {
    // 4 alpha.exe + 3 beta.exe, interleaved. alpha crosses the threshold (grouped),
    // beta does not (individual). The O(n) bucketing must reproduce first-appearance
    // ordering — alpha's group emits where alpha first appears, before beta's rows.
    std::vector<TarProcEvent> e{ev(100, "started", 1, 0, "services.exe")};
    const char* names[] = {"alpha.exe", "beta.exe", "alpha.exe", "beta.exe",
                           "alpha.exe", "beta.exe", "alpha.exe"};
    std::uint32_t pid = 2000;
    for (const char* nm : names)
        e.push_back(ev(110, "started", pid++, 1, nm));
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "d", "0123456789abcdef0123456789abcdef", "windows");
    CHECK(html.find("tar-tree-group") != std::string::npos);      // alpha grouped
    CHECK(html.find("\xC3\x97" "4") != std::string::npos);        // "×4"
    CHECK(html.find("alpha.exe") < html.find("beta.exe"));        // first-appearance order
}

TEST_CASE("tar render: wide distinct-name fan-out stays ungrouped and complete",
          "[tar][tree][render]") {
    // 200 distinct-name children under one parent: none reaches the group threshold,
    // so every child renders individually (exercises the O(n) bucketing at scale).
    std::vector<TarProcEvent> e{ev(100, "started", 1, 0, "root")};
    for (std::uint32_t i = 0; i < 200; ++i)
        e.push_back(ev(110, "started", 2000 + i, 1, ("proc" + std::to_string(i)).c_str()));
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    auto html = render_tar_tree_fragment(t, {}, "d", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find("tar-tree-group") == std::string::npos);
    CHECK(html.find("proc0") != std::string::npos);   // first child rendered
    CHECK(html.find("proc199") != std::string::npos); // last child rendered
}

TEST_CASE("tar tree: a branch deeper than the render cap sets depth_capped",
          "[tar][tree][cap]") {
    // Linear chain deeper than kTarRenderDepthCap → the count pass flags depth_capped
    // and the banner warns the count includes hidden descendants.
    std::vector<TarProcEvent> e;
    const std::uint32_t depth = static_cast<std::uint32_t>(kTarRenderDepthCap) + 20;
    e.push_back(ev(100, "started", 1, 0, "p1"));
    for (std::uint32_t i = 2; i <= depth; ++i)
        e.push_back(ev(100, "started", i, i - 1, ("p" + std::to_string(i)).c_str()));
    auto a = compute_tar_anchors(e);
    auto t = reconstruct_tar_process_tree(e, 0, 1000, a);
    CHECK(t.depth_capped);
    auto html = render_tar_tree_fragment(t, {}, "d", "0123456789abcdef0123456789abcdef", "linux");
    CHECK(html.find("deeper than the display limit") != std::string::npos);

    // A shallow tree must NOT flag depth_capped.
    std::vector<TarProcEvent> shallow{ev(100, "started", 1, 0, "root"),
                                      ev(110, "started", 2, 1, "child")};
    auto t2 = reconstruct_tar_process_tree(shallow, 0, 1000, compute_tar_anchors(shallow));
    CHECK(!t2.depth_capped);
}

TEST_CASE("tar canonical_tar_preset: allowlist passes, garbage → 10m default",
          "[tar][tree][audit]") {
    for (const char* ok : {"on_boot", "on_install", "1m", "10m", "1h", "1d", "custom"})
        CHECK(canonical_tar_preset(ok) == ok);
    CHECK(canonical_tar_preset("") == "10m");
    CHECK(canonical_tar_preset("bogus") == "10m");
    // An injection attempt is canonicalized away (no audit-field forgery survives).
    CHECK(canonical_tar_preset("x command_id=forged") == "10m");
    CHECK(canonical_tar_preset("10m\r\nnodes=0") == "10m");
}

TEST_CASE("tar normalize_tar_os: maps to a closed audit-safe set", "[tar][tree][audit]") {
    CHECK(normalize_tar_os("Windows 11 Pro") == "windows");
    CHECK(normalize_tar_os("Microsoft Windows") == "windows");
    CHECK(normalize_tar_os("Ubuntu 22.04") == "linux");
    CHECK(normalize_tar_os("debian") == "linux");
    CHECK(normalize_tar_os("macOS 14") == "macos");
    CHECK(normalize_tar_os("Darwin") == "macos");
    CHECK(normalize_tar_os("") == "?");
    // An agent-controlled OS carrying structural delimiters can't escape the set.
    CHECK(normalize_tar_os("win\ndows evil=1") == "windows");
    CHECK(normalize_tar_os("totally unknown os") == "?");
}

// =============================================================================
// Device DNS / ARP panels (ADR-0015) — parsers + current-state reduction + escape
// =============================================================================

TEST_CASE("parse_tar_dns_output: schema-located, skips torn/error rows", "[tar][dns][panel]") {
    const std::string out =
        "__schema__|name|record_type|data|ttl_remaining_s|source|ts|action\n"
        "example.com|A|93.184.216.34|60|cache|100|appeared\n"
        "torn-row-missing-cells\n"
        "evil.test|A|10.0.0.9|30|cache|101|appeared\n"
        "total|2\n";
    auto rows = parse_tar_dns_output(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "example.com");
    CHECK(rows[0].record_type == "A");
    CHECK(rows[0].ttl_remaining_s == 60);
    CHECK(rows[0].action == "appeared");
    CHECK(rows[1].name == "evil.test");
}

TEST_CASE("parse_tar_dns_output: an error| payload yields no rows", "[tar][dns][panel]") {
    CHECK(parse_tar_dns_output("error|dns source disabled\n").empty());
}

TEST_CASE("render_tar_dns_panel: newest-wins, removed dropped, fields escaped",
          "[tar][dns][panel]") {
    // Rows are newest-first. A 'removed' newest action drops the binding; an older
    // duplicate of an already-seen key is ignored.
    std::vector<TarDnsCacheEntry> rows = {
        {200, "gone.test", "A", "1.2.3.4", 5, "cache", "removed"},
        {150, "keep.test", "A", "<script>", 9, "cache", "appeared"},
        {100, "keep.test", "A", "<script>", 60, "cache", "appeared"}, // older dup — ignored
    };
    const std::string html = render_tar_dns_panel(rows);
    CHECK(html.find("keep.test") != std::string::npos);
    CHECK(html.find("gone.test") == std::string::npos);          // removed → omitted
    CHECK(html.find("&lt;script&gt;") != std::string::npos);     // agent field escaped
    CHECK(html.find("<script>") == std::string::npos);           // never raw
    CHECK(html.find("devnet-count\">1<") != std::string::npos);  // one current entry
}

TEST_CASE("parse_tar_arp_output + render_tar_arp_panel", "[tar][arp][panel]") {
    const std::string out =
        "__schema__|interface|ip_address|mac_address|entry_type|ts|action\n"
        "Ethernet|192.168.1.1|aa:bb:cc:dd:ee:ff|dynamic|100|appeared\n"
        "Ethernet|192.168.1.9|11:22:33:44:55:66|static|90|removed\n";
    auto rows = parse_tar_arp_output(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].iface == "Ethernet");
    CHECK(rows[0].ip_address == "192.168.1.1");
    const std::string html = render_tar_arp_panel(rows);
    CHECK(html.find("192.168.1.1") != std::string::npos);
    CHECK(html.find("192.168.1.9") == std::string::npos); // removed → omitted
}

TEST_CASE("render_tar_capture_sources: rows, badges, staged toggles, device attr",
          "[tar][capture-sources]") {
    const std::string status =
        "config|process_enabled|true\nconfig|process_live_rows|18204\n"
        "config|arp_enabled|false\nconfig|arp_live_rows|0\n"
        "config|dns_enabled|true\nconfig|dns_live_rows|42\n";
    const std::string compat =
        "header|source|os|status|capture_method|notes\n"
        "row|arp|windows|supported|iphlpapi|x\nrow|arp|linux|planned|procfs|y\n"
        "row|dns|windows|supported|dnsapi|x\n";
    const std::string html = render_tar_capture_sources("agent-123", status, compat);
    CHECK(html.find("data-device=\"agent-123\"") != std::string::npos);
    CHECK(html.find("always on") != std::string::npos);             // process is locked
    CHECK(html.find("data-source=\"arp\"") != std::string::npos);   // arp is a staged toggle
    CHECK(html.find("badge-new") != std::string::npos);             // arp/dns NEW badge
    CHECK(html.find("badge-pii") != std::string::npos);             // dns PII badge
    CHECK(html.find("stageCapToggle(this)") != std::string::npos);  // guardrail wiring
    CHECK(html.find("capApplyBar") != std::string::npos);           // push bar present
}

TEST_CASE("render_tar_dns_panel: newest-first input is a load-bearing invariant (ADR-0015)",
          "[tar][dns][panel]") {
    // The route feeds rows ORDER BY ts DESC; the reduction is newest-wins. Pin that
    // the ORDER BY is load-bearing — a future refactor dropping it would corrupt the
    // panel (the wrong row would win per key).
    std::vector<TarDnsCacheEntry> newest_first = {
        {200, "x.test", "A", "1.1.1.1", 5, "cache", "removed"},   // newest action: removed
        {100, "x.test", "A", "1.1.1.1", 60, "cache", "appeared"}, // older
    };
    CHECK(render_tar_dns_panel(newest_first).find("devnet-count\">0<") !=
          std::string::npos); // removed wins → empty cache

    std::vector<TarDnsCacheEntry> oldest_first = {
        {100, "x.test", "A", "1.1.1.1", 60, "cache", "appeared"},
        {200, "x.test", "A", "1.1.1.1", 5, "cache", "removed"},
    };
    // Fed oldest-first the FIRST-seen (appeared) wrongly wins → entry shown. This is
    // the documented wrong result the route's ORDER BY prevents.
    CHECK(render_tar_dns_panel(oldest_first).find("devnet-count\">1<") != std::string::npos);
}
