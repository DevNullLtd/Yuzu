/// @file test_live_model.cpp
/// Pure-unit tests for live_model.{hpp,cpp}: the ONE live-read kind table and the
/// plugin-output parsers hoisted out of device_routes.cpp (#2146). The route-level
/// render pins live in test_device_routes.cpp; these pin the pure functions directly.

#include "live_model.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <functional>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;
namespace live = yuzu::server::live;

namespace {

const std::vector<std::string>& all_kinds() {
    static const std::vector<std::string> k = {
        "uptime",      "processes",  "process_tree",  "services",      "users",
        "netconfig",   "arp",        "dns_cache",     "listening",     "connections",
        "capture_sources", "disk",   "hw_disks",      "hw_memory",     "hw_processors",
        "hw_drivers",  "battery",    "thermal",       "smart",         "volumes",
        "adapters",    "wifi"};
    return k;
}

} // namespace

TEST_CASE("live kind table: one table, 22 dashboard kinds", "[live][model]") {
    REQUIRE(all_kinds().size() == 22);
    std::set<std::string> seen_pairs;
    for (const auto& k : all_kinds()) {
        CAPTURE(k);
        const auto lk = live::resolve_dashboard_kind(k);
        REQUIRE(lk);
        CHECK_FALSE(lk->plugin.empty());
        CHECK_FALSE(lk->action.empty());
        CHECK_FALSE(lk->label.empty());
        // Each kind keeps its own audit verb (works-council countability).
        CHECK(lk->audit_action == "device.live." + k);
        // A secondary dispatch is declared as a pair or not at all.
        CHECK(lk->plugin2.empty() == lk->action2.empty());
        // Generic pipe-row kinds declare a prefix and columns together.
        CHECK(lk->row_prefix.empty() == lk->columns.empty());
        seen_pairs.insert(lk->plugin + "/" + lk->action + "/" + lk->plugin2 + "/" + lk->action2);
    }
    // No two kinds resolve to the same dispatch (process_tree and processes differ by action).
    CHECK(seen_pairs.size() == 22);
}

// CO-2: the 22 `device.live.<kind>` audit verbs, written out as literals. The works-council
// access-audit posture counts each kind separately, so a renamed token must not rename its
// verb silently: this list is compared to the table both as a set and per token.
TEST_CASE("live kind table: the 22 audit verbs are pinned as literals", "[live][model][audit]") {
    const std::vector<std::pair<std::string, std::string>> expected = {
        {"uptime", "device.live.uptime"},
        {"processes", "device.live.processes"},
        {"process_tree", "device.live.process_tree"},
        {"services", "device.live.services"},
        {"users", "device.live.users"},
        {"netconfig", "device.live.netconfig"},
        {"arp", "device.live.arp"},
        {"dns_cache", "device.live.dns_cache"},
        {"listening", "device.live.listening"},
        {"connections", "device.live.connections"},
        {"capture_sources", "device.live.capture_sources"},
        {"disk", "device.live.disk"},
        {"hw_disks", "device.live.hw_disks"},
        {"hw_memory", "device.live.hw_memory"},
        {"hw_processors", "device.live.hw_processors"},
        {"hw_drivers", "device.live.hw_drivers"},
        {"battery", "device.live.battery"},
        {"thermal", "device.live.thermal"},
        {"smart", "device.live.smart"},
        {"volumes", "device.live.volumes"},
        {"adapters", "device.live.adapters"},
        {"wifi", "device.live.wifi"}};
    REQUIRE(expected.size() == 22);
    std::set<std::string> expected_verbs;
    std::set<std::string> table_verbs;
    for (const auto& [token, verb] : expected) {
        CAPTURE(token);
        expected_verbs.insert(verb);
        const auto lk = live::resolve_dashboard_kind(token);
        REQUIRE(lk);
        CHECK(lk->audit_action == verb);
        table_verbs.insert(lk->audit_action);
    }
    CHECK(expected_verbs.size() == 22);
    CHECK(table_verbs == expected_verbs);
}

// QE-4: the table has exactly the 22 pinned rows. The table is private, so the check runs
// through the public resolvers: every pinned token resolves, and made-up neighbours of the
// pinned tokens (a plausible 23rd kind, the DEX perf names, singular/plural and case
// variants) do not.
TEST_CASE("live kind table: exactly the 22 pinned tokens resolve", "[live][model]") {
    std::size_t resolved = 0;
    for (const auto& k : all_kinds())
        if (live::resolve_dashboard_kind(k))
            ++resolved;
    CHECK(resolved == 22);
    for (const char* k : {"hw_battery", "hw_thermal", "hw_smart", "hw_volumes", "hw_wifi",
                          "hw_adapters", "service", "user", "disks", "process", "connection",
                          "listen", "dns", "capture", "perf", "perf_hourly", "uptime2", "Disk",
                          "WIFI", "hw_"}) {
        CAPTURE(k);
        CHECK_FALSE(live::resolve_dashboard_kind(k));
        CHECK_FALSE(live::resolve_rest_kind(k));
    }
}

TEST_CASE("live kind table: REST subset is exactly uptime + processes", "[live][model]") {
    std::set<std::string> rest;
    for (const auto& k : all_kinds())
        if (live::resolve_rest_kind(k))
            rest.insert(k);
    // This exact-set pin is the tripwire for a positional mis-port of the in-flight #8122's
    // `bool escaped_rows` into LiveKind: a positional `true` after `columns` would silently
    // bind to `rest_v1` and widen the REST surface to a dashboard-only kind, which this
    // check turns into a failure. Do not loosen it to a subset check.
    CHECK(rest == std::set<std::string>{"uptime", "processes"});
    // The REST view is the SAME row as the dashboard view, not a second table.
    for (const char* k : {"uptime", "processes"}) {
        const auto d = live::resolve_dashboard_kind(k);
        const auto r = live::resolve_rest_kind(k);
        REQUIRE(d);
        REQUIRE(r);
        CHECK(d->plugin == r->plugin);
        CHECK(d->action == r->action);
        CHECK(d->audit_action == r->audit_action);
    }
    const auto up = live::resolve_rest_kind("uptime");
    REQUIRE(up);
    CHECK(up->plugin == "os_info");
    CHECK(up->action == "uptime");
    const auto pr = live::resolve_rest_kind("processes");
    REQUIRE(pr);
    CHECK(pr->plugin == "processes");
    CHECK(pr->action == "list_hashed");
}

TEST_CASE("live kind table: unknown or malformed tokens resolve to nothing", "[live][model]") {
    for (const char* k : {"", "UPTIME", "Uptime", "uptime ", " uptime", "process_tree/", "dex_perf",
                          "dex_procperf", "echo", "../uptime", "uptime\n"}) {
        CAPTURE(k);
        CHECK_FALSE(live::resolve_dashboard_kind(k));
        CHECK_FALSE(live::resolve_rest_kind(k));
    }
    // process_tree is dashboard-only.
    CHECK(live::resolve_dashboard_kind("process_tree"));
    CHECK_FALSE(live::resolve_rest_kind("process_tree"));
}

TEST_CASE("live kind table: process_tree carries the secondary connections dispatch",
          "[live][model]") {
    const auto lk = live::resolve_dashboard_kind("process_tree");
    REQUIRE(lk);
    CHECK(lk->plugin == "processes");
    CHECK(lk->action == "list_tree");
    CHECK(lk->plugin2 == "network_diag");
    CHECK(lk->action2 == "connections");
}

TEST_CASE("live helpers: split_lines and pipe_fields", "[live][model]") {
    CHECK(live::split_lines("a\r\n\nb\nc") == std::vector<std::string>{"a", "b", "c"});
    CHECK(live::split_lines("").empty());
    CHECK(live::pipe_fields("a||c|") == std::vector<std::string>{"a", "", "c", ""});
    CHECK(live::pipe_fields("") == std::vector<std::string>{""});
}

TEST_CASE("live parsers: processes and uptime", "[live][model]") {
    const auto p = live::parse_processes("proc|4|System||\nproc|xx|n|h|p\nproc|5\nproc|7|a|b\n");
    REQUIRE(p.size() == 3);
    CHECK(p[0].pid == 4);
    CHECK(p[0].name == "System");
    CHECK(p[1].pid == 0); // unparseable pid keeps the row at 0
    CHECK(p[2].name == "a");
    CHECK(p[2].sha256 == "b");
    const auto u = live::parse_uptime("uptime_display|1d\nuptime_seconds|86400\nuptime_seconds|bad\n");
    REQUIRE(u.display);
    CHECK(*u.display == "1d");
    REQUIRE(u.seconds);
    CHECK(*u.seconds == 86400);
    CHECK_FALSE(live::parse_uptime("garbage").display);
}

TEST_CASE("live parsers: process tree guards uint32 narrowing", "[live][model][security]") {
    const auto nodes = live::parse_process_tree(
        "proc|4|0|System||\nproc|4294967296|4|huge|x|y\nproc|9|4294967296|ppidhuge|\n"
        "proc|zz|0|bad|\nproc|1|2\n");
    // The over-UINT32_MAX pid row and the unparseable-pid row are dropped; the over-range
    // ppid becomes the root sentinel 0 rather than truncating.
    REQUIRE(nodes.size() == 2);
    CHECK(nodes[0].pid == 4);
    CHECK(nodes[1].pid == 9);
    CHECK(nodes[1].ppid == 0);
    const auto conns = live::parse_process_conns(
        "conn|tcp|1.1.1.1|80|2.2.2.2|443|800\nconn|tcp|1|2|3|4|4294967296\nconn|tcp|1|2|3\n");
    REQUIRE(conns.size() == 1);
    CHECK(conns[0].pid == 800);
    CHECK(conns[0].remote_addr == "2.2.2.2");
    CHECK(conns[0].remote_port == 443);
    CHECK(conns[0].local_port == 80);
}

TEST_CASE("live parsers: services shapes follow the device OS, then the sniff", "[live][model]") {
    SECTION("Windows 5-field with a numeric display name stays Windows when the OS is known") {
        const auto s = live::parse_services("svc|wuauserv|123|Stopped|Manual\n", "windows");
        REQUIRE(s.rows.size() == 1);
        CHECK(s.rows[0].display == "123");
        CHECK(s.rows[0].status == "Stopped");
        CHECK(s.running == 0);
    }
    SECTION("macOS 5-field: pid column is not the display name") {
        const auto s = live::parse_services("svc|com.a|1234|running|auto\n", "Darwin");
        REQUIRE(s.rows.size() == 1);
        CHECK(s.rows[0].display.empty());
        CHECK(s.rows[0].status == "running");
        CHECK(s.running == 1);
    }
    SECTION("unknown OS, 4-field: numeric or dash pid column sniffs as macOS") {
        const auto s = live::parse_services("svc|a|12|running\nsvc|b|-|stopped\nsvc|c|running|desc\n", "");
        REQUIRE(s.rows.size() == 3);
        CHECK(s.rows[0].status == "running");
        CHECK(s.rows[1].status == "stopped");
        CHECK(s.rows[2].status == "running");
        CHECK(s.rows[2].display == "desc");
        CHECK(s.running == 2);
    }
    // QE-2: the OS and the pid-column sniff disagree. A known OS wins over the sniff, so the
    // result differs from what the unknown-OS sniff would give for the same row.
    SECTION("known Linux, 4-field row with a numeric column 2: the Linux shape wins over the sniff") {
        // The sniff alone would call `12` a macOS pid (status=running, display empty).
        const auto s = live::parse_services("svc|a|12|running\n", "linux");
        REQUIRE(s.rows.size() == 1);
        CHECK(s.rows[0].name == "a");
        CHECK(s.rows[0].status == "12");      // Linux svc|name|status|description
        CHECK(s.rows[0].display == "running"); // the description column
        CHECK(s.rows[0].startup.empty());
        CHECK(s.running == 0); // "12" does not contain "run"
    }
    SECTION("known macOS, 4-field row: macOS shape even for an OS string in another case") {
        for (const char* os : {"darwin", "macos", "Darwin", "MacOS"}) {
            CAPTURE(os);
            const auto s = live::parse_services("svc|com.a|1234|running\n", os);
            REQUIRE(s.rows.size() == 1);
            CHECK(s.rows[0].name == "com.a");
            CHECK(s.rows[0].status == "running"); // svc|label|pid|status
            CHECK(s.rows[0].display.empty());
            CHECK(s.running == 1);
        }
    }
    SECTION("known macOS, 4-field row whose pid column is a non-numeric word") {
        // The sniff would read `word` as a Linux status; the known OS says macOS.
        const auto s = live::parse_services("svc|com.b|word|stopped\n", "darwin");
        REQUIRE(s.rows.size() == 1);
        CHECK(s.rows[0].status == "stopped");
        CHECK(s.rows[0].display.empty());
        CHECK(s.running == 0);
    }
    SECTION("unknown OS, 5-field row with a numeric column 2 defaults to the Windows shape (UP-5/UP-6)") {
        const auto s = live::parse_services("svc|x|123|Stopped|Manual\n", "");
        REQUIRE(s.rows.size() == 1);
        CHECK(s.rows[0].name == "x");
        CHECK(s.rows[0].display == "123"); // not misread as a macOS pid
        CHECK(s.rows[0].status == "Stopped");
        CHECK(s.rows[0].startup == "Manual");
        CHECK(s.running == 0);
    }
    SECTION("rows of the wrong arity are skipped; a longer row keeps the leading shape") {
        CHECK(live::parse_services("svc|only\nsvc|a|b\nother|x\n", "").rows.empty());
    }
}

TEST_CASE("live parsers: disk clamps percent and ignores unmeasured volumes",
          "[live][model][security]") {
    const auto d = live::parse_disk("disk|C:|1000|400|60\ndisk|D:|0|0|150\ndisk|E:|500|100|-5\n"
                                    "disk|short\n");
    REQUIRE(d.rows.size() == 3);
    CHECK(d.rows[1].percent_used == 100); // clamped
    CHECK(d.rows[2].percent_used == 0);   // clamped
    CHECK(d.worst_used == 60);            // D: has total 0, so it cannot drive the figure
    CHECK(live::parse_disk("disk|C:|0|0|50\n").worst_used == -1);
}

TEST_CASE("live parsers: capture sources only list what the agent reported", "[live][model]") {
    const auto c = live::parse_capture_sources(
        "config|process_enabled|true\nconfig|process_rows|42\nconfig|tcp_enabled|false\n"
        "config|bogus_enabled|true\nconfig|dns_enabled|true\nconfig|dns_rows|nan\n");
    REQUIRE(c.rows.size() == 3);
    CHECK(c.on == 2);
    CHECK(c.rows[0].name == "process");
    CHECK(c.rows[0].live_rows == 42);
    CHECK(c.rows[1].name == "tcp");
    CHECK(c.rows[1].live_rows == -1);
    CHECK(c.rows[2].name == "dns");
    CHECK(c.rows[2].live_rows == -1); // unparseable count stays unknown
}

TEST_CASE("live parsers: small typed kinds", "[live][model]") {
    const auto users = live::parse_users("user|alice|h|t|s\nuser|bob\nuser\n");
    REQUIRE(users.size() == 2);
    CHECK(users[1].host.empty());
    const auto nets = live::parse_netconfig("ip|eth0|10.0.0.5|24|10.0.0.1\nip|lo|127.0.0.1|8|0.0.0.0\n"
                                            "ip|x|1.1.1.1|bad|-\nip|short\n");
    REQUIRE(nets.size() == 3);
    CHECK(nets[0].gateway == "10.0.0.1");
    CHECK(nets[1].gateway.empty());
    CHECK(nets[2].prefix == 0);
    const auto arp = live::parse_arp("arp|eth0|10.0.0.2|-|static\narp|a|b\n");
    REQUIRE(arp.size() == 1);
    CHECK(arp[0].mac.empty());
    const auto dns = live::parse_dns_cache("cache_entry|a.example|A\ncache_entry|not_available|x\n"
                                           "cache_entry|only\n");
    REQUIRE(dns.size() == 1);
    CHECK(dns[0].name == "a.example");
    const auto lis = live::parse_listening("listen|tcp|0.0.0.0|22|100\nlisten|tcp|::|nan\nlisten|tcp\n");
    REQUIRE(lis.size() == 2);
    CHECK(lis[0].pid == 100);
    CHECK(lis[1].port == 0);
    const auto conn = live::parse_connections("conn|tcp|a|1|b|2|9\nconn|tcp|a|1|b\n");
    REQUIRE(conn.size() == 1);
    CHECK(conn[0].local == "a:1");
    CHECK(conn[0].remote == "b:2");
    CHECK(conn[0].state == "ESTABLISHED");
}

TEST_CASE("live parsers: generic rows pad, trim and preserve foreign lines", "[live][model]") {
    const auto lk = live::resolve_dashboard_kind("hw_disks");
    REQUIRE(lk);
    const auto g = live::parse_generic_rows(
        *lk, "disk|0|Model|931|SSD|NVMe\ndisk|1|short\nwarning|odd line\ndisk|2|a|b|c|d|extra\n");
    REQUIRE(g.rows.size() == 3);
    CHECK(g.rows[0] == std::vector<std::string>{"0", "Model", "931", "SSD", "NVMe"});
    CHECK(g.rows[1] == std::vector<std::string>{"1", "short", "", "", ""}); // padded
    CHECK(g.rows[2].size() == 5);                                           // trimmed
    REQUIRE(g.raw_rows.size() == 1);
    CHECK(g.raw_rows[0] == "warning|odd line");
}

TEST_CASE("live parsers: generic rows and users stop at kMaxLiveRows", "[live][model][security]") {
    const auto lk = live::resolve_dashboard_kind("hw_memory");
    REQUIRE(lk);
    std::string big;
    for (std::size_t i = 0; i < live::kMaxLiveRows + 50; ++i)
        big += "dimm|0|1|DDR4|1\n";
    CHECK(live::parse_generic_rows(*lk, big).rows.size() == live::kMaxLiveRows);
    std::string big_users;
    for (std::size_t i = 0; i < live::kMaxLiveRows + 50; ++i)
        big_users += "user|u\n";
    CHECK(live::parse_users(big_users).size() == live::kMaxLiveRows);
}

// QE-3: every parser that applies kMaxLiveRows, at cap-1, cap and cap+1 input rows. The
// boundary rows catch a `>=` that became `>` (one row too many) or a cap that stopped one
// short. parse_processes and parse_capture_sources are NOT capped by kMaxLiveRows (bounded by
// the ingest size cap instead), so they are not in this table.
TEST_CASE("live parsers: each capped parser holds the kMaxLiveRows boundary", "[live][model][security]") {
    struct Capped {
        const char* name;
        const char* line; // one valid row, newline-terminated
        std::function<std::size_t(const std::string&)> parse;
    };
    const auto hw = live::resolve_dashboard_kind("hw_memory");
    REQUIRE(hw);
    const std::vector<Capped> table = {
        {"services", "svc|n|d|running|auto\n",
         [](const std::string& o) { return live::parse_services(o, "windows").rows.size(); }},
        {"disk", "disk|C:|100|50|50\n",
         [](const std::string& o) { return live::parse_disk(o).rows.size(); }},
        {"connections", "conn|tcp|1.1.1.1|1|2.2.2.2|2|9\n",
         [](const std::string& o) { return live::parse_connections(o).size(); }},
        {"process_conns", "conn|tcp|1.1.1.1|1|2.2.2.2|2|9\n",
         [](const std::string& o) { return live::parse_process_conns(o).size(); }},
        {"process_tree", "proc|4|0|n|h|p\n",
         [](const std::string& o) { return live::parse_process_tree(o).size(); }},
        {"users", "user|u|h|t|s\n",
         [](const std::string& o) { return live::parse_users(o).size(); }},
        {"netconfig", "ip|eth0|10.0.0.5|24|10.0.0.1\n",
         [](const std::string& o) { return live::parse_netconfig(o).size(); }},
        {"arp", "arp|eth0|10.0.0.2|aa:bb|dynamic\n",
         [](const std::string& o) { return live::parse_arp(o).size(); }},
        {"dns_cache", "cache_entry|a.example|A\n",
         [](const std::string& o) { return live::parse_dns_cache(o).size(); }},
        {"listening", "listen|tcp|0.0.0.0|22|100\n",
         [](const std::string& o) { return live::parse_listening(o).size(); }},
        {"generic rows", "dimm|0|1|DDR4|1\n",
         [&hw](const std::string& o) { return live::parse_generic_rows(*hw, o).rows.size(); }},
    };
    for (const auto& c : table) {
        CAPTURE(c.name);
        for (const std::size_t n : {live::kMaxLiveRows - 1, live::kMaxLiveRows, live::kMaxLiveRows + 1}) {
            CAPTURE(n);
            std::string input;
            input.reserve(n * 40);
            for (std::size_t i = 0; i < n; ++i)
                input += c.line;
            CHECK(c.parse(input) == std::min(n, live::kMaxLiveRows));
        }
    }
}

// What parse_generic_rows ACTUALLY does with its two bounds (the code applies two checks, not
// one shared cap): a raw (foreign-prefix) line is kept only while rows + raw_rows is below
// kMaxLiveRows, and a data row is kept until rows alone reaches kMaxLiveRows, then parsing
// stops. So the combined total can reach 2 x kMaxLiveRows. This records the current
// behaviour (the comments in live_model.{hpp,cpp} state the same); it is not a design claim.
TEST_CASE("live parsers: generic rows bound rows and raw rows by two separate checks",
          "[live][model][security]") {
    const auto lk = live::resolve_dashboard_kind("hw_memory");
    REQUIRE(lk);
    constexpr std::size_t kCap = live::kMaxLiveRows;
    const auto repeat = [](const char* line, std::size_t n) {
        std::string s;
        for (std::size_t i = 0; i < n; ++i)
            s += line;
        return s;
    };
    SECTION("raw lines alone stop at the cap") {
        for (const std::size_t n : {kCap - 1, kCap, kCap + 1}) {
            CAPTURE(n);
            const auto g = live::parse_generic_rows(*lk, repeat("warning|x\n", n));
            CHECK(g.rows.empty());
            CHECK(g.raw_rows.size() == std::min(n, kCap));
        }
    }
    SECTION("a full raw set does not stop the data rows: the total reaches 2 x cap") {
        const auto g = live::parse_generic_rows(
            *lk, repeat("warning|x\n", kCap + 10) + repeat("dimm|0|1|DDR4|1\n", kCap + 10));
        CHECK(g.raw_rows.size() == kCap);
        CHECK(g.rows.size() == kCap);
        CHECK(g.rows.size() + g.raw_rows.size() == 2 * kCap);
    }
    SECTION("data rows first leave no room for raw lines once rows reach the cap") {
        const auto g = live::parse_generic_rows(
            *lk, repeat("dimm|0|1|DDR4|1\n", kCap) + repeat("warning|x\n", 10));
        CHECK(g.rows.size() == kCap);
        CHECK(g.raw_rows.empty()); // parsing stopped at the cap, the trailing raw lines were not read
    }
    SECTION("raw lines are admitted only while the combined count is below the cap") {
        const auto g = live::parse_generic_rows(
            *lk, repeat("dimm|0|1|DDR4|1\n", kCap - 5) + repeat("warning|x\n", 20));
        CHECK(g.rows.size() == kCap - 5);
        CHECK(g.raw_rows.size() == 5); // (kCap - 5) + 5 == kCap, the 6th raw line is dropped
    }
}
