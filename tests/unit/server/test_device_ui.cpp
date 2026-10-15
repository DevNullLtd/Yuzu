/// @file test_device_ui.cpp
/// Unit tests for the shared device-page PURE renderers (device_ui.cpp): the
/// fleet list, the Device-info / DEX / Guardian lenses. Data in, HTML out — no
/// store, no network.

#include "device_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

TEST_CASE("device list: rows drill, filters echo, score badge", "[device][ui]") {
    DeviceRow d;
    d.agent_id = "agent-123456789abc";
    d.hostname = "WS-1";
    d.os = "windows";
    d.arch = "x86_64";
    d.agent_version = "0.12.0";
    d.online = true;
    d.last_seen = "now";
    d.dex_score = 82;
    const auto html = render_devices_list_fragment({d}, "", "all", "all", 1, 1);
    CHECK(html.find("WS-1") != std::string::npos);
    CHECK(html.find("/device?id=") != std::string::npos); // row drills to the device page
    CHECK(html.find(">82<") != std::string::npos);         // DEX score badge
    CHECK(html.find("Windows") != std::string::npos);
    // empty result set is an honest placeholder, not a crash
    CHECK(render_devices_list_fragment({}, "zzz", "all", "all", 0, 0).find("No devices match") !=
          std::string::npos);
}

TEST_CASE("device info lens: real fields; hardware honestly deferred", "[device][ui]") {
    DeviceRow d;
    d.agent_id = "a-1";
    d.hostname = "WS-1";
    d.os = "linux";
    d.arch = "x86_64";
    const auto html = render_device_info_fragment(d);
    CHECK(html.find("WS-1") != std::string::npos);
    CHECK(html.find("Identity") != std::string::npos);
    CHECK(html.find("inventory") != std::string::npos); // hardware/owner not fabricated
}

// #3564/WS-A4: the single-device page/info path repopulates the Tags field from
// DeviceApi's per-device tag read (get_one). Locks the render so a future
// refactor of DeviceRow.tags -> render_device_info_fragment cannot silently
// regress to the "always empty" bug this seam commit fixed (happy-path Gate 8 F1).
TEST_CASE("device info lens: tags render key=value; empty -> none", "[device][ui]") {
    SECTION("populated tags render, escaped, comma-joined") {
        DeviceRow d;
        d.agent_id = "a-2";
        d.hostname = "WS-2";
        d.tags = {"env=prod", "role=db"};
        const auto html = render_device_info_fragment(d);
        CHECK(html.find("env=prod") != std::string::npos);
        CHECK(html.find("role=db") != std::string::npos);
        CHECK(html.find(">none<") == std::string::npos); // placeholder absent when tags present
    }
    SECTION("no tags -> 'none' placeholder, never a fabricated tag") {
        DeviceRow d;
        d.agent_id = "a-3";
        d.hostname = "WS-3";
        // d.tags left empty (the list path, and a device with no tags)
        const auto html = render_device_info_fragment(d);
        CHECK(html.find(">none<") != std::string::npos);
    }
}

TEST_CASE("device DEX lens: score + signals + empty state", "[device][ui]") {
    std::vector<std::pair<std::string, std::int64_t>> sigs{{"process.crashed", 3}};
    const auto html = render_device_dex_lens("a-1", 71, sigs);
    CHECK(html.find("DEX experience") != std::string::npos);
    CHECK(html.find(">71<") != std::string::npos);
    CHECK(html.find("App crash") != std::string::npos); // dex_signal_label(process.crashed)
    const auto empty = render_device_dex_lens("a-1", 100, {});
    CHECK(empty.find("No DEX signals") != std::string::npos);
}

TEST_CASE("device Guardian lens: compliance summary + per-guard + empty", "[device][ui]") {
    std::vector<DeviceGuardRow> guards{{"Defender RTP", "compliant", "2026-06-16T10:00:00Z"},
                                       {"BitLocker", "drifted", "2026-06-16T10:00:00Z"}};
    const auto html = render_device_guardian_lens("a-1", guards);
    CHECK(html.find("Defender RTP") != std::string::npos);
    CHECK(html.find("Compliant") != std::string::npos); // summary tile label
    CHECK(html.find("50%") != std::string::npos);        // 1 of 2 compliant
    CHECK(html.find("drifted") != std::string::npos);    // state badge text
    CHECK(render_device_guardian_lens("a-1", {}).find("No guards evaluated") != std::string::npos);
}

TEST_CASE("device page: live-info button enabled online, disabled offline", "[device][ui]") {
    DeviceRow d;
    d.agent_id = "a-1";
    d.hostname = "WS-1";
    d.os = "windows";
    d.online = true;
    const auto on = render_device_page(d);
    CHECK(on.find("Get live info") != std::string::npos);
    // online → loads the live snapshot
    CHECK(on.find("/fragments/device/live?id=a-1") != std::string::npos);
    CHECK(on.find("device-live") != std::string::npos); // result mount present
    CHECK(on.find("disabled") == std::string::npos);    // button enabled

    d.online = false;
    const auto off = render_device_page(d);
    CHECK(off.find("disabled") != std::string::npos); // offline → disabled
    CHECK(off.find("device offline") != std::string::npos);
}

TEST_CASE("device live shell: collapsible cards + KPI strip + chrome", "[device][ui]") {
    const auto html = render_device_live_shell("a-1");
    // Each card auto-loads its REAL plugin instruction via the run route on render.
    CHECK(html.find("/fragments/device/live/run?id=a-1&amp;kind=uptime") != std::string::npos);
    CHECK(html.find("/fragments/device/live/run?id=a-1&amp;kind=process_tree") != std::string::npos);
    CHECK(html.find("/fragments/device/live/run?id=a-1&amp;kind=connections") != std::string::npos);
    CHECK(html.find("hx-trigger=\"load\"") != std::string::npos); // fires on render, no 30s wait
    CHECK(html.find("class=\"ls-card\"") != std::string::npos);   // collapsible cards
    CHECK(html.find("id=\"ls-kpi-uptime\"") != std::string::npos); // KPI tiles (filled via OOB)
    CHECK(html.find("id=\"ls-kpi-procs\"") != std::string::npos);
    CHECK(html.find("lsToggleAll(this)") != std::string::npos);   // expand/collapse all
    CHECK(html.find("lsPopOut(event,this)") != std::string::npos); // per-card pop-out
    CHECK(html.find("Processes") != std::string::npos);
    CHECK(html.find("Capture sources") != std::string::npos);
}

TEST_CASE("device live value: value tile; empty -> dash", "[device][ui]") {
    const auto html = render_device_live_value("Uptime", "2d 18h 4m");
    CHECK(html.find("2d 18h 4m") != std::string::npos);
    CHECK(html.find("Uptime") != std::string::npos);
    CHECK(render_device_live_value("Uptime", "").find("&mdash;") != std::string::npos);
}

TEST_CASE("device live processes: hash table, search, first-10 preview", "[device][ui]") {
    std::vector<LiveProcess> procs{
        {1234, "chrome.exe",
         "abcdef0123456789aabbccddeeff00112233445566778899aabbccddeeff0011", "C:\\chrome.exe"},
        {5678, "code.exe", "", ""}}; // unresolved hash/path
    const auto html = render_device_live_processes(procs);
    CHECK(html.find("1234") != std::string::npos);
    CHECK(html.find("chrome.exe") != std::string::npos);
    CHECK(html.find("running processes") != std::string::npos);
    CHECK(html.find("SHA-256") != std::string::npos);                       // column header
    CHECK(html.find("abcdef0123456789\xE2\x80\xA6") != std::string::npos);  // truncated hash + …
    CHECK(html.find("title=\"abcdef0123456789aabb") != std::string::npos);  // full hash in title
    CHECK(html.find("C:\\chrome.exe") != std::string::npos);                // path shown
    CHECK(html.find("&mdash;") != std::string::npos);                       // missing hash -> dash
    CHECK(html.find("gpSearchTopN") != std::string::npos);                  // searchable
    CHECK(html.find("data-gplimit=\"10\"") != std::string::npos);
    CHECK(render_device_live_processes({}).find("No processes returned") != std::string::npos);
    // first-10 preview: rows beyond 10 render into the DOM but are hidden.
    std::vector<LiveProcess> many;
    for (int i = 0; i < 15; ++i)
        many.push_back({i, "p" + std::to_string(i), "", ""});
    const auto big = render_device_live_processes(many);
    CHECK(big.find("display:none") != std::string::npos);     // rows 11+ hidden
    CHECK(big.find("Showing 10 of 15") != std::string::npos); // preview counter
}

// ── Live-snapshot v2 renderers (feat/device-live-snapshot) ──────────────────

TEST_CASE("device live tree: nesting, hash, net join, suspicious flag, escaping", "[device][ui]") {
    std::vector<LiveProcNode> nodes{
        {4, 0, "System", "", ""},
        {800, 4, "explorer.exe", "abc123def456", "C:\\Windows\\explorer.exe"},
        {860, 4, "excel.exe", "e0e0", "C:\\Office\\excel.exe"}, // suspicious PARENT
        {900, 860, "powershell.exe", "ffee", ""},     // excel -> powershell: FLAGGED (LOLBin spawn)
        {950, 900, "<evil>", "dd", ""},               // agent-controlled name must be escaped
    };
    std::vector<LiveConn> conns{{800, "140.82.112.4", 443, 52000, false}};
    const auto html = render_device_live_tree(nodes, conns);
    CHECK(html.find("explorer.exe") != std::string::npos);
    CHECK(html.find("tar-tree-node") != std::string::npos);             // TAR tree markup
    CHECK(html.find("abc123def456") != std::string::npos);             // hash on the node
    CHECK(html.find("140.82.112.4:443") != std::string::npos);         // joined connection chip
    CHECK(html.find("tt-net-pub") != std::string::npos);               // public endpoint highlighted
    CHECK(html.find("lsFilterTree(this)") != std::string::npos);       // name/PID/hash search bar
    CHECK(html.find("tt-anom") != std::string::npos);                  // excel->powershell flagged
    CHECK(html.find("data-anom=\"1\"") != std::string::npos);          // the suspicious row carries it
    CHECK(html.find("&lt;evil&gt;") != std::string::npos);             // name HTML-escaped
    CHECK(html.find("<evil>") == std::string::npos);                   // never raw
    CHECK(render_device_live_tree({}, {}).find("No processes returned") != std::string::npos);
}

TEST_CASE("device live tree: same-name siblings grouped; cycle is bounded", "[device][ui]") {
    std::vector<LiveProcNode> nodes{{4, 0, "services.exe", "", ""}};
    for (std::uint32_t i = 0; i < 8; ++i) // 8 svchost under services -> grouped (>=5)
        nodes.push_back({100 + i, 4, "svchost.exe", "h", ""});
    const auto html = render_device_live_tree(nodes, {});
    CHECK(html.find("tt-group-count") != std::string::npos); // "×8" group
    CHECK(html.find("\xC3\x97" "8") != std::string::npos);
    // A 2-cycle (A<->B as each other's parent) must not hang or crash — both are roots
    // (ppid present but mutual), bounded by the depth/node caps.
    std::vector<LiveProcNode> cyc{{10, 11, "a.exe", "", ""}, {11, 10, "b.exe", "", ""}};
    const auto safe = render_device_live_tree(cyc, {});
    CHECK(safe.find("a.exe") != std::string::npos);
}

TEST_CASE("device live ARP / DNS / sockets / services / users / netconfig renderers",
          "[device][ui]") {
    SECTION("arp: type pills + empty note + escaping") {
        std::vector<LiveArpEntry> rows{{"Ethernet", "10.0.0.1", "00:1a:2b:3c:4d:5e", "dynamic"},
                                       {"Ethernet", "10.0.0.9", "", "incomplete"},
                                       {"<script>", "10.0.0.2", "aa", "dynamic"}}; // agent-controlled iface
        const auto h = render_device_live_arp(rows);
        CHECK(h.find("00:1a:2b:3c:4d:5e") != std::string::npos);
        CHECK(h.find("dynamic") != std::string::npos);
        CHECK(h.find("&lt;script&gt;") != std::string::npos); // iface HTML-escaped
        CHECK(h.find("<script>") == std::string::npos);
        CHECK(render_device_live_arp({}).find("not available on this platform") !=
              std::string::npos);
    }
    SECTION("dns: searchable, escaped, empty note") {
        std::vector<LiveDnsEntry> rows{{"github.com", "A"}, {"<x>", "AAAA"}};
        const auto h = render_device_live_dns(rows);
        CHECK(h.find("github.com") != std::string::npos);
        CHECK(h.find("lsFilterRows(this)") != std::string::npos);
        CHECK(h.find("&lt;x&gt;") != std::string::npos);
        CHECK(render_device_live_dns({}).find("no resolver cache") != std::string::npos);
    }
    SECTION("listening + connections") {
        const auto l = render_device_live_listening({{"tcp", "0.0.0.0", 445, 4}});
        CHECK(l.find("445") != std::string::npos);
        const auto c = render_device_live_connections({{"tcp", "10.0.0.5:52000", "1.2.3.4:443", "ESTABLISHED"}});
        CHECK(c.find("1.2.3.4:443") != std::string::npos);
        CHECK(c.find("ESTABLISHED") != std::string::npos);
    }
    SECTION("services: running highlighted, searchable, escaped") {
        std::vector<LiveService> rows{{"Spooler", "Print Spooler", "Running", "Automatic"},
                                      {"wuauserv", "Windows Update", "Stopped", "Manual"},
                                      {"x", "<b>Display</b>", "Running", "Manual"}}; // agent-controlled display
        const auto h = render_device_live_services(rows);
        CHECK(h.find("Print Spooler") != std::string::npos);
        CHECK(h.find("Running") != std::string::npos);
        CHECK(h.find("lsFilterRows(this)") != std::string::npos);
        CHECK(h.find("&lt;b&gt;Display&lt;/b&gt;") != std::string::npos); // display escaped
        CHECK(h.find("<b>Display</b>") == std::string::npos);
    }
    SECTION("users + netconfig + connections escaping") {
        const auto u = render_device_live_users({{"<u>", "local", "Interactive", "console"}});
        CHECK(u.find("&lt;u&gt;") != std::string::npos); // username escaped
        CHECK(u.find("<u>") == std::string::npos);
        const auto n = render_device_live_netconfig({{"<a>", "10.0.0.5", 24, "10.0.0.1"}});
        CHECK(n.find("10.0.0.5") != std::string::npos);
        CHECK(n.find("&lt;a&gt;") != std::string::npos); // adapter escaped
        const auto c = render_device_live_connections({{"tcp", "10.0.0.5:1", "<r>:443", "ESTABLISHED"}});
        CHECK(c.find("&lt;r&gt;:443") != std::string::npos); // remote escaped
        CHECK(c.find("<r>:443") == std::string::npos);
    }
}

TEST_CASE("device live capture sources: toggle state + $-table + read-only link", "[device][ui]") {
    std::vector<LiveCaptureSource> rows{{"process", "Process", "Activity", true, 1234},
                                        {"arp", "ARP", "Network", false, -1}};
    const auto h = render_device_live_capture_sources(rows);
    CHECK(h.find("$Process_Live") != std::string::npos);
    CHECK(h.find("1234") != std::string::npos);
    CHECK(h.find("ls-sw on") != std::string::npos);  // process enabled (toggle on)
    CHECK(h.find("src-off") != std::string::npos);   // arp disabled
    CHECK(h.find("/tar") != std::string::npos);      // configure-on-TAR link (read-only here)
    CHECK(render_device_live_capture_sources({}).find("not running") != std::string::npos);
}

TEST_CASE("device live disk: usage-bar tones, low-free floor, clamp, unmeasured, escaping",
          "[device][ui]") {
    constexpr long long kGiB = 1024LL * 1024 * 1024;
    SECTION("ok tone: ample free, human-readable sizes") {
        const auto h = render_device_live_disk({{"C:\\", 500 * kGiB, 200 * kGiB, 60}});
        CHECK(h.find("ls-bar-ok") != std::string::npos);
        CHECK(h.find("60%") != std::string::npos);
        CHECK(h.find("500.0 GiB") != std::string::npos); // human() formats the raw bytes
    }
    SECTION("red tone mirrors BOTH halves of storage.low (>=90% used OR <5GiB free)") {
        const auto full = render_device_live_disk({{"/", 100 * kGiB, 1 * kGiB, 99}});
        CHECK(full.find("ls-bar-bad") != std::string::npos);
        // 70% used but only 2 GiB free → still red via the low-free floor.
        const auto lowfree = render_device_live_disk({{"/", 100 * kGiB, 2 * kGiB, 70}});
        CHECK(lowfree.find("ls-bar-bad") != std::string::npos);
    }
    SECTION("warn tone: 75-90% used with ample free") {
        const auto h = render_device_live_disk({{"/", 1000 * kGiB, 200 * kGiB, 80}});
        CHECK(h.find("ls-bar-warn") != std::string::npos);
    }
    SECTION("unmeasured (total<=0) renders a dash, never a false-healthy bar") {
        const auto h = render_device_live_disk({{"/", 0, 0, 0}});
        CHECK(h.find("&mdash;") != std::string::npos);
        CHECK(h.find("ls-bar-ok") == std::string::npos);
    }
    SECTION("percent clamped into [0,100]") {
        const auto h = render_device_live_disk({{"/", 10 * kGiB, 0, 150}});
        CHECK(h.find("100%") != std::string::npos);
        CHECK(h.find("150%") == std::string::npos);
    }
    SECTION("path HTML-escaped; empty -> note") {
        const auto h = render_device_live_disk({{"<x>", 1024, 512, 50}});
        CHECK(h.find("&lt;x&gt;") != std::string::npos);
        CHECK(h.find("<x>") == std::string::npos);
        CHECK(render_device_live_disk({}).find("No volume reported") != std::string::npos);
    }
}
