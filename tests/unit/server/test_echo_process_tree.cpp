/// @file test_echo_process_tree.cpp
/// Unit tests for the Echo process-tree engine (echo_process_tree.*): the hourly
/// __schema__ parsers, the whole-hour window math, the name-level tree over one selected
/// hour (self-parent, cycles and fan-in each place every node once), the by-name anomaly
/// flags, and render HTML-escaping + the capture-source cards. Pure — no store, no
/// network. Package acceptance is fixture-only: parent_name and abnormal_exit_count are
/// not populated by the agent until the fold writes them.

#include "echo_process_tree.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server;

// The Echo page shell is a raw-string constant in its own TU (echo_page_ui.cpp), at global scope.
extern const char* const kEchoPageHtml;

namespace {

constexpr std::int64_t kHour = 3600;
const std::string kToken = "0123456789abcdef0123456789abcdef";

EchoProcHourRow hr(std::int64_t hour, const char* name, const char* parent, const char* user = "",
                   std::int64_t starts = 1, std::int64_t stops = 0, std::int64_t abnormal = 0) {
    EchoProcHourRow r;
    r.hour_ts = hour;
    r.name = name;
    r.parent_name = parent;
    r.user = user;
    r.start_count = starts;
    r.stop_count = stops;
    r.abnormal_exit_count = abnormal;
    return r;
}

// First node with `name` (and `user` when given); nullptr if absent.
const EchoProcNode* find_node(const EchoProcTree& t, const std::string& name,
                              const char* user = nullptr) {
    for (const auto& n : t.nodes)
        if (n.name == name && (!user || n.user == user))
            return &n;
    return nullptr;
}

int count_of(const std::string& hay, const std::string& needle) {
    int c = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++c;
    return c;
}

// Number of rendered tree rows carrying this exact process name.
int rendered_rows(const std::string& html, const std::string& name) {
    return count_of(html, "<span class=\"tt-name\">" + name + "</span>");
}

EchoTcpHourRow conn(std::int64_t hour, const char* proc, const char* raddr, int rport,
                    const char* proto = "tcp", std::int64_t connects = 1) {
    EchoTcpHourRow c;
    c.hour_ts = hour;
    c.process_name = proc;
    c.remote_addr = raddr;
    c.remote_port = rport;
    c.proto = proto;
    c.connect_count = connects;
    return c;
}

std::string lower(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

// =============================================================================
// Parsers
// =============================================================================

TEST_CASE("echo parse: process hourly __schema__ output", "[echo][tree][parse]") {
    // Columns located by NAME (deliberately reordered), a trailer row and a torn row.
    const std::string out =
        "__schema__|user|name|hour_ts|stop_count|start_count|parent_name|abnormal_exit_count\n"
        "root|systemd|7200|0|1||0\n"
        "alice|bash|7200|3|4|systemd|2\n"
        "torn|row\n"
        "total|2\n"; // trailer row: too few cells, must be skipped
    const auto rows = parse_echo_process_hourly_output(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].hour_ts == 7200);
    CHECK(rows[0].name == "systemd");
    CHECK(rows[0].parent_name.empty());
    CHECK(rows[0].start_count == 1);
    CHECK(rows[1].name == "bash");
    CHECK(rows[1].user == "alice");
    CHECK(rows[1].parent_name == "systemd");
    CHECK(rows[1].start_count == 4);
    CHECK(rows[1].stop_count == 3);
    CHECK(rows[1].abnormal_exit_count == 2);
}

TEST_CASE("echo parse: process hourly rejects a missing required column and an error payload",
          "[echo][tree][parse]") {
    CHECK(parse_echo_process_hourly_output("error|database is locked\n").empty());
    const std::string cols[] = {"hour_ts", "name", "parent_name", "user", "start_count", "stop_count"};
    for (const auto& dropped : cols) {
        std::string schema = "__schema__";
        std::string row;
        for (const auto& c : cols) {
            if (c == dropped)
                continue;
            schema += "|" + c;
            row += (row.empty() ? "" : "|") + std::string(c == "name" || c == "parent_name" || c == "user"
                                                              ? "x"
                                                              : "5");
        }
        INFO("dropped " << dropped);
        CHECK(parse_echo_process_hourly_output(schema + "\n" + row + "\n").empty());
    }
    // abnormal_exit_count is optional: its absence is not a wrong shape.
    CHECK(parse_echo_process_hourly_output("__schema__|hour_ts|name|parent_name|user|start_count|stop_count\n"
                                           "3600|a||u|1|1\n")
              .size() == 1);
}

TEST_CASE("echo parse: process hourly skips torn rows and out-of-range numbers",
          "[echo][tree][parse]") {
    const std::string out =
        "__schema__|hour_ts|name|parent_name|user|start_count|stop_count|abnormal_exit_count\n"
        "3600|ok||u|1|1|0\n"
        "3600|torn||u|1|1\n"                      // shorter than the abnormal column
        "abc|bad-hour||u|1|1|0\n"                 // non-numeric required cell
        "3600|neg||u|-4|1|0\n"                    // negative count
        "3600|huge||u|99999999999999999999|1|0\n" // overflows int64
        "3600|garbage-optional||u|2|2|zzz\n";     // optional measure → 0, row kept
    const auto rows = parse_echo_process_hourly_output(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "ok");
    CHECK(rows[1].name == "garbage-optional");
    CHECK(rows[1].abnormal_exit_count == 0);
}

TEST_CASE("echo parse: process hourly is bounded by max_rows", "[echo][tree][parse]") {
    std::string out = "__schema__|hour_ts|name|parent_name|user|start_count|stop_count\n";
    for (int i = 0; i < 50; ++i)
        out += "3600|n" + std::to_string(i) + "||u|1|1\n";
    CHECK(parse_echo_process_hourly_output(out, 10).size() == 10);
}

TEST_CASE("echo parse: tcp hourly __schema__ output", "[echo][tree][parse]") {
    const std::string out =
        "__schema__|hour_ts|remote_addr|remote_port|proto|process_name|connect_count|"
        "disconnect_count|failed_count\n"
        "7200|1.2.3.4|443|tcp|bash|5|4|1\n"
        "7200|5.6.7.8|99999|tcp|bash|1|1|0\n"; // out-of-range port → 0, row kept
    const auto conns = parse_echo_tcp_hourly_output(out);
    REQUIRE(conns.size() == 2);
    CHECK(conns[0].hour_ts == 7200);
    CHECK(conns[0].process_name == "bash");
    CHECK(conns[0].remote_addr == "1.2.3.4");
    CHECK(conns[0].remote_port == 443);
    CHECK(conns[0].connect_count == 5);
    CHECK(conns[0].disconnect_count == 4);
    CHECK(conns[0].failed_count == 1);
    CHECK(conns[1].remote_port == 0);
    // The join key is required.
    CHECK(parse_echo_tcp_hourly_output("__schema__|hour_ts|remote_addr\n7200|1.2.3.4\n").empty());
    CHECK(parse_echo_tcp_hourly_output("error|nope\n").empty());
}

TEST_CASE("echo parse: dns hourly schema-located, skips torn/error rows", "[echo][dns][panel]") {
    const std::string out =
        "__schema__|hour_ts|name|record_type|data|appear_count|remove_count|negative_count\n"
        "7200|example.com|A|93.184.216.34|3|2|0\n"
        "torn-row-missing-cells\n"
        "7200|evil.test|A||0|0|5\n"
        "total|2\n";
    const auto rows = parse_echo_dns_hourly_output(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].name == "example.com");
    CHECK(rows[0].record_type == "A");
    CHECK(rows[0].appear_count == 3);
    CHECK(rows[0].remove_count == 2);
    CHECK(rows[1].negative_count == 5);
    CHECK(parse_echo_dns_hourly_output("error|dns source disabled\n").empty());
    CHECK(parse_echo_dns_hourly_output("__schema__|hour_ts|name\n7200|x\n").empty());
}

TEST_CASE("echo parse: arp hourly schema-located", "[echo][arp][panel]") {
    const std::string out =
        "__schema__|hour_ts|interface|ip_address|mac_address|appear_count|remove_count|is_router|"
        "rebind_count\n"
        "7200|eth0|10.0.0.1|aa:bb:cc:dd:ee:ff|1|0|1|0\n"
        "7200|eth0|10.0.0.7|11:22:33:44:55:66|2|2|0|3\n";
    const auto rows = parse_echo_arp_hourly_output(out);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].iface == "eth0");
    CHECK(rows[0].is_router);
    CHECK_FALSE(rows[1].is_router);
    CHECK(rows[1].rebind_count == 3);
    CHECK(parse_echo_arp_hourly_output("__schema__|hour_ts|interface\n7200|eth0\n").empty());
}

// =============================================================================
// Presets + window math
// =============================================================================

TEST_CASE("echo canonical_echo_preset: allowlist passes, garbage → 24h default",
          "[echo][tree][audit]") {
    for (const char* ok : {"1h", "24h", "7d", "custom"})
        CHECK(canonical_echo_preset(ok) == ok);
    // The retired anchors and sub-hour presets are no longer tokens.
    for (const char* gone : {"on_boot", "on_install", "1m", "10m", "1d"})
        CHECK(canonical_echo_preset(gone) == "24h");
    CHECK(canonical_echo_preset("") == "24h");
    CHECK(canonical_echo_preset("bogus") == "24h");
    // An injection attempt is canonicalized away (no audit-field forgery survives).
    CHECK(canonical_echo_preset("x command_id=forged") == "24h");
    CHECK(canonical_echo_preset("24h\r\nnodes=0") == "24h");
}

TEST_CASE("echo window: presets map to whole hourly buckets ending at the last complete hour",
          "[echo][tree][window]") {
    const std::int64_t now = 1'000'000'000 + 1234; // mid-hour: the current hour is not complete
    const std::int64_t last = (now / kHour) * kHour - kHour;

    auto w = resolve_echo_window("1h", 0, 0, now);
    CHECK(w.from_ts == last);
    CHECK(w.to_ts == last);
    w = resolve_echo_window("24h", 0, 0, now);
    CHECK(w.to_ts == last);
    CHECK(w.from_ts == last - 23 * kHour);
    w = resolve_echo_window("7d", 0, 0, now);
    CHECK(w.to_ts == last);
    CHECK(w.from_ts == last - 167 * kHour);
    CHECK(w.from_ts % kHour == 0);
    // Garbage and the retired tokens fall back to the 24h default.
    for (const char* bad : {"garbage", "", "10m", "on_boot"}) {
        w = resolve_echo_window(bad, 0, 0, now);
        CHECK(w.from_ts == last - 23 * kHour);
        CHECK(w.to_ts == last);
    }
    // An hour-aligned `now` still ends at the hour BEFORE it.
    CHECK(resolve_echo_window("1h", 0, 0, 100 * kHour).to_ts == 99 * kHour);
    // Early epoch: the start is clamped at 0, never negative.
    w = resolve_echo_window("24h", 0, 0, 10000);
    CHECK(w.from_ts == 0);
    CHECK(w.to_ts == kHour);
}

TEST_CASE("echo window: custom range floors to the hour; unset ends default; reversed collapses",
          "[echo][tree][window]") {
    const std::int64_t now = 1'000'000'000;
    const std::int64_t last = (now / kHour) * kHour - kHour;

    auto w = resolve_echo_window("custom", 5000 * kHour + 17, 5010 * kHour + 3599, now);
    CHECK(w.from_ts == 5000 * kHour);
    CHECK(w.to_ts == 5010 * kHour);
    // Unset `to` → the last complete hour; unset `from` → 23 hours before `to`.
    w = resolve_echo_window("custom", last - 5 * kHour + 9, 0, now);
    CHECK(w.from_ts == last - 5 * kHour);
    CHECK(w.to_ts == last);
    w = resolve_echo_window("custom", 0, 0, now);
    CHECK(w.to_ts == last);
    CHECK(w.from_ts == last - 23 * kHour);
    // A reversed range collapses to a single bucket at `from`.
    w = resolve_echo_window("custom", 5000 * kHour + 7, 4000 * kHour + 9, now);
    CHECK(w.from_ts == 5000 * kHour);
    CHECK(w.to_ts == w.from_ts);
    // A wide range is clamped to the 168-hour span, keeping the newest hours.
    w = resolve_echo_window("custom", 1 * kHour, 9000 * kHour, now);
    CHECK(w.to_ts == 9000 * kHour);
    CHECK(w.from_ts == 9000 * kHour - 167 * kHour);
}

// =============================================================================
// Name-level tree
// =============================================================================

TEST_CASE("echo tree: echo_process_hours lists distinct hours newest first", "[echo][tree]") {
    const std::vector<EchoProcHourRow> rows{hr(7200, "a", ""), hr(3600, "b", ""), hr(7200, "c", ""),
                                            hr(10800, "d", "")};
    CHECK(echo_process_hours(rows) == std::vector<std::int64_t>{10800, 7200, 3600});
    CHECK(echo_process_hours({}).empty());
}

TEST_CASE("echo tree: three hours each build their own name-level tree", "[echo][tree]") {
    const std::int64_t h1 = 3600, h2 = 7200, h3 = 10800;
    const std::vector<EchoProcHourRow> rows{
        // hour 1: systemd -> bash
        hr(h1, "systemd", "", "root", 1, 0), hr(h1, "bash", "systemd", "alice", 2, 2),
        // hour 2: systemd -> {bash, cron}; bash -> ls
        hr(h2, "systemd", "", "root", 1, 0), hr(h2, "bash", "systemd", "alice", 5, 4),
        hr(h2, "cron", "systemd", "root", 1, 1), hr(h2, "ls", "bash", "alice", 9, 9),
        // hour 3: only an orphan whose parent is not in this hour
        hr(h3, "ls", "bash", "alice", 1, 1)};

    const auto t1 = build_echo_process_tree(rows, h1);
    CHECK(t1.hour_ts == h1);
    REQUIRE(t1.nodes.size() == 2);
    REQUIRE(t1.roots.size() == 1);
    CHECK(t1.nodes[t1.roots[0]].name == "systemd");
    CHECK(t1.nodes[t1.roots[0]].children.size() == 1);
    CHECK(t1.start_total == 3);

    const auto t2 = build_echo_process_tree(rows, h2);
    REQUIRE(t2.nodes.size() == 4);
    REQUIRE(t2.roots.size() == 1);
    const auto* sd = find_node(t2, "systemd");
    const auto* bash = find_node(t2, "bash");
    const auto* ls = find_node(t2, "ls");
    REQUIRE((sd && bash && ls));
    CHECK(sd->children.size() == 2);
    CHECK(t2.nodes[bash->parent].name == "systemd");
    CHECK(t2.nodes[ls->parent].name == "bash");
    CHECK(ls->start_count == 9);
    // Siblings are ordered by name: bash before cron.
    CHECK(t2.nodes[sd->children[0]].name == "bash");
    CHECK(t2.nodes[sd->children[1]].name == "cron");

    const auto t3 = build_echo_process_tree(rows, h3);
    REQUIRE(t3.nodes.size() == 1);
    REQUIRE(t3.roots.size() == 1); // the parent "bash" is not in this hour → a root
    CHECK(t3.nodes[0].name == "ls");

    // An hour with no rows is an empty tree, not an error.
    const auto none = build_echo_process_tree(rows, 99 * kHour);
    CHECK(none.nodes.empty());
    CHECK(none.roots.empty());
}

TEST_CASE("echo tree: a row whose parent_name equals its own name is a root, rendered once",
          "[echo][tree][cycle]") {
    const std::vector<EchoProcHourRow> rows{hr(3600, "bash", "bash", "alice", 4, 4),
                                            hr(3600, "ls", "bash", "alice", 2, 2)};
    const auto t = build_echo_process_tree(rows, 3600);
    REQUIRE(t.nodes.size() == 2);
    REQUIRE(t.roots.size() == 1);
    CHECK(t.nodes[t.roots[0]].name == "bash");
    CHECK(t.nodes[t.roots[0]].children.size() == 1); // ls hangs under it, bash not under itself
    const auto html = render_echo_tree_fragment(t, {}, kToken);
    CHECK(rendered_rows(html, "bash") == 1);
    CHECK(rendered_rows(html, "ls") == 1);
}

TEST_CASE("echo tree: a 2-cycle places every node once and terminates", "[echo][tree][cycle]") {
    const std::vector<EchoProcHourRow> rows{hr(3600, "a", "b", "u"), hr(3600, "b", "a", "u")};
    const auto t = build_echo_process_tree(rows, 3600);
    REQUIRE(t.nodes.size() == 2);
    REQUIRE(t.roots.size() == 1);
    // The cycle is cut at its lowest-index member: a is the root, b hangs under it.
    CHECK(t.nodes[t.roots[0]].name == "a");
    REQUIRE(t.nodes[t.roots[0]].children.size() == 1);
    CHECK(t.nodes[t.nodes[t.roots[0]].children[0]].name == "b");
    const auto html = render_echo_tree_fragment(t, {}, kToken);
    CHECK(rendered_rows(html, "a") == 1);
    CHECK(rendered_rows(html, "b") == 1);
}

TEST_CASE("echo tree: a longer cycle with a tail renders every node exactly once",
          "[echo][tree][cycle]") {
    // cmd -> conhost -> cmd, plus `tail` hanging off the loop: cmd/conhost/cmd by construction.
    const std::vector<EchoProcHourRow> rows{hr(3600, "tail", "conhost", "u"),
                                            hr(3600, "cmd", "conhost", "u"),
                                            hr(3600, "conhost", "cmd", "u")};
    const auto t = build_echo_process_tree(rows, 3600);
    REQUIRE(t.nodes.size() == 3);
    REQUIRE(t.roots.size() == 1);
    int reachable = 0;
    std::vector<std::size_t> stack{t.roots[0]};
    while (!stack.empty()) {
        const auto id = stack.back();
        stack.pop_back();
        ++reachable;
        for (const auto c : t.nodes[id].children)
            stack.push_back(c);
    }
    CHECK(reachable == 3);
    const auto html = render_echo_tree_fragment(t, {}, kToken);
    for (const char* n : {"tail", "cmd", "conhost"})
        CHECK(rendered_rows(html, n) == 1);
}

TEST_CASE("echo tree: a name with two parents is placed once under the first, counts summed",
          "[echo][tree][fan-in]") {
    const std::vector<EchoProcHourRow> rows{
        hr(3600, "p1", "", "u", 1, 0),          hr(3600, "p2", "", "u", 1, 0),
        hr(3600, "x", "p1", "u", 3, 2, 1),      // first row: parent p1 wins
        hr(3600, "x", "p2", "u", 4, 4, 0)};     // same (name, user), other parent
    const auto t = build_echo_process_tree(rows, 3600);
    REQUIRE(t.nodes.size() == 3);
    const auto* x = find_node(t, "x");
    REQUIRE(x != nullptr);
    CHECK(t.nodes[x->parent].name == "p1");
    CHECK(x->parent_name == "p1");
    CHECK(x->start_count == 7);
    CHECK(x->stop_count == 6);
    CHECK(x->abnormal_exit_count == 1);
    CHECK(find_node(t, "p2")->children.empty());
    CHECK(rendered_rows(render_echo_tree_fragment(t, {}, kToken), "x") == 1);
}

TEST_CASE("echo tree: the same name under two users is two nodes; the parent link is by name",
          "[echo][tree][fan-in]") {
    const std::vector<EchoProcHourRow> rows{
        hr(3600, "svchost", "", "SYSTEM", 18, 17), hr(3600, "svchost", "", "NETWORK SERVICE", 6, 6),
        hr(3600, "wuauserv", "svchost", "SYSTEM", 1, 1)};
    const auto t = build_echo_process_tree(rows, 3600);
    REQUIRE(t.nodes.size() == 3);
    REQUIRE(t.roots.size() == 2);
    // The child attaches to the FIRST svchost in row order, never to both.
    const auto* first = find_node(t, "svchost", "SYSTEM");
    const auto* second = find_node(t, "svchost", "NETWORK SERVICE");
    REQUIRE((first && second));
    CHECK(first->children.size() == 1);
    CHECK(second->children.empty());
    CHECK(rendered_rows(render_echo_tree_fragment(t, {}, kToken), "wuauserv") == 1);
}

TEST_CASE("echo tree: a 5000-deep chain terminates and stops at the depth guard",
          "[echo][tree][cap]") {
    std::vector<EchoProcHourRow> rows;
    rows.push_back(hr(3600, "n0", ""));
    for (int i = 1; i < 5000; ++i)
        rows.push_back(hr(3600, ("n" + std::to_string(i)).c_str(), ("n" + std::to_string(i - 1)).c_str()));
    const auto t = build_echo_process_tree(rows, 3600);
    REQUIRE(t.nodes.size() == 5000);
    REQUIRE(t.roots.size() == 1);
    CHECK(t.depth_capped);
    const auto html = render_echo_tree_fragment(t, {}, kToken);
    CHECK(html.find("deeper than the display limit") != std::string::npos);
    CHECK(html.find("(depth capped)") != std::string::npos);
    // The render stops at the cap: far fewer rows than nodes.
    CHECK(count_of(html, "class=\"echo-tree-row\"") <= kEchoRenderDepthCap + 2);

    // A shallow tree must NOT flag depth_capped.
    CHECK_FALSE(build_echo_process_tree({hr(3600, "root", ""), hr(3600, "child", "root")}, 3600)
                    .depth_capped);
}

TEST_CASE("echo tree: more distinct names than the node cap sets truncated", "[echo][tree][cap]") {
    std::vector<EchoProcHourRow> rows;
    rows.reserve(kEchoTreeMaxNodes + 5);
    for (std::size_t i = 0; i < kEchoTreeMaxNodes + 5; ++i)
        rows.push_back(hr(3600, ("p" + std::to_string(i)).c_str(), ""));
    const auto t = build_echo_process_tree(rows, 3600);
    CHECK(t.truncated);
    CHECK(t.nodes.size() == kEchoTreeMaxNodes);
    CHECK(render_echo_tree_fragment(t, {}, kToken).find("exceeds the render limit") != std::string::npos);
}

TEST_CASE("echo anomaly: suspicious parent->child flagged, abnormal exits flagged, benign not",
          "[echo][tree][anomaly]") {
    std::string evidence;
    CHECK(echo_is_suspicious_spawn("winword.exe", "powershell.exe", &evidence));
    CHECK(evidence.find("winword.exe") != std::string::npos);
    CHECK_FALSE(echo_is_suspicious_spawn("explorer.exe", "cmd.exe")); // benign — explorer excluded
    CHECK_FALSE(echo_is_suspicious_spawn("bash", "ls"));

    const std::vector<EchoProcHourRow> rows{
        hr(3600, "init", "", "root"),
        hr(3600, "winword.exe", "init", "bob"),
        hr(3600, "powershell.exe", "winword.exe", "bob"),
        hr(3600, "explorer.exe", "init", "bob"),
        hr(3600, "cmd.exe", "explorer.exe", "bob"),
        hr(3600, "crasher", "init", "bob", 2, 2, 3)};
    const auto t = build_echo_process_tree(rows, 3600);
    CHECK(find_node(t, "powershell.exe")->anomaly);
    CHECK_FALSE(find_node(t, "cmd.exe")->anomaly);
    CHECK_FALSE(find_node(t, "winword.exe")->anomaly);
    const auto* crasher = find_node(t, "crasher");
    CHECK(crasher->anomaly);
    CHECK(crasher->anomaly_evidence.find("3 abnormal exit") != std::string::npos);
    CHECK(t.anomaly_count == 2);
    CHECK(t.abnormal_total == 3);
    // The full tree is never pruned: anomalies-only filtering is client-side.
    CHECK(t.nodes.size() == 6);
    const auto html = render_echo_tree_fragment(t, {}, kToken);
    CHECK(html.find("data-anom=\"1\"") != std::string::npos);
    CHECK(html.find("data-anom=\"0\"") != std::string::npos);
}

TEST_CASE("echo anomaly: a name with more stops than starts is a soft flag, not an anomaly",
          "[echo][tree][anomaly]") {
    const auto t = build_echo_process_tree({hr(3600, "daemon", "", "root", 1, 4)}, 3600);
    const auto* d = find_node(t, "daemon");
    REQUIRE(d != nullptr);
    CHECK(d->stops_exceed_starts);
    CHECK_FALSE(d->anomaly);
    CHECK(render_echo_tree_fragment(t, {}, kToken).find("more stops than starts") != std::string::npos);
    CHECK_FALSE(build_echo_process_tree({hr(3600, "ok", "", "root", 2, 2)}, 3600)
                    .nodes[0]
                    .stops_exceed_starts);
}

TEST_CASE("echo anomaly: denylist is basename-stripped and case-insensitive", "[echo][tree][anomaly]") {
    CHECK(echo_is_suspicious_spawn("C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                                  "POWERSHELL.EXE"));
    CHECK(echo_is_suspicious_spawn("/opt/MsEdge/msedge.exe", "Cmd.Exe"));
    CHECK_FALSE(echo_is_suspicious_spawn("notepad.exe", "powershell.exe")); // benign parent
}

// =============================================================================
// Render
// =============================================================================

TEST_CASE("echo render: rows carry data-anom and the hour's counts, no pid or run state",
          "[echo][tree][render]") {
    const auto t = build_echo_process_tree({hr(7200, "bash", "", "alice", 3, 2, 1)}, 7200);
    const auto html = render_echo_tree_fragment(t, {}, kToken);
    CHECK(html.find("detail?token=" + kToken + "&amp;node=0") != std::string::npos);
    CHECK(html.find("data-anom=\"1\"") != std::string::npos);
    CHECK(html.find("started 3 &middot; stopped 2 &middot; 1 abnormal") != std::string::npos);
    CHECK(html.find("1970-01-01T02:00:00Z") != std::string::npos); // the hour in the banner
    CHECK(html.find("data-state") == std::string::npos);
    CHECK(html.find("tt-pid") == std::string::npos);
    CHECK(html.find("names only") != std::string::npos);
    CHECK(html.find("$Process_Hourly") != std::string::npos);
}

TEST_CASE("echo render: an empty hour says so", "[echo][tree][render]") {
    const auto html = render_echo_tree_fragment(build_echo_process_tree({}, 0), {}, kToken);
    CHECK(html.find("echo-tree-empty") != std::string::npos);
    CHECK(html.find("echo-tree-row") == std::string::npos);
}

TEST_CASE("echo render: net summary joins by name, dedups, orders public first, labels listeners",
          "[echo][tree][render][net]") {
    const auto t = build_echo_process_tree({hr(7200, "proc", ""), hr(7200, "other", "")}, 7200);
    const std::vector<EchoTcpHourRow> conns{
        conn(7200, "proc", "203.0.113.9", 443), // public (sorts first, shown inline)
        conn(7200, "proc", "203.0.113.9", 443), // duplicate → deduped
        conn(7200, "proc", "", 0),              // listener (2nd distinct, shown inline)
        conn(7200, "stranger", "198.51.100.1", 80)};
    const auto html = render_echo_tree_fragment(t, conns, kToken);
    CHECK(html.find("listening") != std::string::npos);
    CHECK(html.find("203.0.113.9:443") != std::string::npos);
    CHECK(html.find("tt-ep-pub") != std::string::npos); // public endpoint highlighted
    // 2 distinct endpoints (one dup removed): badge count "2" appears in the net cell.
    CHECK(html.find("tt-net-ico\">\xE2\x86\x97</span>2") != std::string::npos);
    // A connection under another name is not attached to either node.
    CHECK(html.find("198.51.100.1") == std::string::npos);
    CHECK(count_of(html, "tt-net-ico") == 1);
}

TEST_CASE("echo render: agent-controlled fields are HTML-escaped", "[echo][tree][render]") {
    const auto t = build_echo_process_tree(
        {hr(3600, "<script>evil</script>", "", "us\"er")}, 3600);
    const auto html = render_echo_tree_fragment(
        t, {conn(3600, "<script>evil</script>", "<img src=x>", 80)}, kToken);
    CHECK(html.find("<script>evil") == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
    CHECK(html.find("<img src=x>") == std::string::npos);
    CHECK(html.find("us\"er") == std::string::npos);

    const auto detail = render_echo_proc_detail(
        t.nodes[0], {conn(3600, "<script>evil</script>", "<img src=x>", 80)});
    CHECK(detail.find("<script>evil") == std::string::npos);
    CHECK(detail.find("<img src=x>") == std::string::npos);
    CHECK(detail.find("&lt;script&gt;") != std::string::npos);
}

TEST_CASE("echo render: detail shows the counts, the parent name and the connections by name",
          "[echo][tree][render]") {
    const auto t = build_echo_process_tree(
        {hr(7200, "systemd", "", "root"), hr(7200, "bash", "systemd", "alice", 3, 4, 2)}, 7200);
    const auto* bash = find_node(t, "bash");
    REQUIRE(bash != nullptr);
    EchoTcpHourRow c = conn(7200, "bash", "1.2.3.4", 443, "tcp", 5);
    c.disconnect_count = 4;
    c.failed_count = 1;
    const auto html = render_echo_proc_detail(*bash, {c});
    CHECK(html.find("echo-detail") != std::string::npos);
    CHECK(html.find(">systemd<") != std::string::npos);       // parent name
    CHECK(html.find("Started in this hour") != std::string::npos);
    CHECK(html.find("Abnormal exits") != std::string::npos);
    CHECK(html.find("more stops than starts") != std::string::npos);
    CHECK(html.find("1.2.3.4:443") != std::string::npos);
    CHECK(html.find("<th>Connects</th>") != std::string::npos);
    CHECK(html.find("Not kept: process ids, command lines and file paths") != std::string::npos);
    CHECK(html.find("pid") == std::string::npos);
    // No connections → the empty line, not an empty table.
    const auto none = render_echo_proc_detail(*bash, {});
    CHECK(none.find("No TCP connections recorded under this name") != std::string::npos);
    CHECK(none.find("<table") == std::string::npos);
}

// ── Hardening-round coverage (governance Gate 3/4) ──────────────────────────

TEST_CASE("echo parse_ts_param: epoch, datetime-local, and rejection", "[echo][tree][parse]") {
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

TEST_CASE("echo parse_ts_param_strict: refuses what the lenient parser reads as unset or shifted",
          "[echo][tree][parse]") {
    CHECK(parse_ts_param_strict("") == std::optional<std::int64_t>{0}); // absent
    CHECK(parse_ts_param_strict("1718000000") == std::optional<std::int64_t>{1718000000});
    CHECK(parse_ts_param_strict("2026-06-18T12:00:00") == std::optional<std::int64_t>{1781784000});
    CHECK(parse_ts_param_strict("2026-06-18T12:00") == std::optional<std::int64_t>{1781784000});
    CHECK_FALSE(parse_ts_param_strict("9999999999999999999")); // 19 digits
    CHECK_FALSE(parse_ts_param_strict("2026-13-01T00:00"));    // invalid month
    CHECK_FALSE(parse_ts_param_strict("99999-01-01T00:00"));   // five-digit year
    CHECK_FALSE(parse_ts_param_strict("not-a-time"));
    CHECK_FALSE(parse_ts_param_strict(" 2026-06-18T12:00:00"));    // leading whitespace
    CHECK_FALSE(parse_ts_param_strict("2026-06-18T12:00:"));       // bare trailing ':'
    CHECK_FALSE(parse_ts_param_strict("2026-06-18T12:00:30xyz"));  // trailing junk
    CHECK_FALSE(parse_ts_param_strict("2026-06-18T12:00:30.123")); // fractional suffix
    CHECK_FALSE(parse_ts_param_strict("2026-+6-+18T+12:+00:+30")); // sign acceptance
    CHECK_FALSE(parse_ts_param_strict("2026-06-18 12:00:00"));     // space instead of 'T'
    CHECK_FALSE(parse_ts_param_strict("-5"));
}

TEST_CASE("echo parse_ts_param_strict: refuses a calendar-impossible date", "[echo][tree][parse]") {
    // The lenient parser rolls these into the next month; the strict one must refuse them.
    CHECK_FALSE(parse_ts_param_strict("2026-02-31T00:00"));
    CHECK_FALSE(parse_ts_param_strict("2026-02-29T00:00")); // 2026 is not a leap year
    CHECK_FALSE(parse_ts_param_strict("2026-04-31T00:00:00"));
    CHECK_FALSE(parse_ts_param_strict("2100-02-29T00:00")); // divisible by 100, not by 400
    CHECK(parse_ts_param_strict("2028-02-29T00:00").has_value()); // leap year
    CHECK(parse_ts_param_strict("2000-02-29T00:00").has_value()); // divisible by 400
    CHECK(parse_ts_param_strict("2026-04-30T23:59:59").has_value());
    CHECK(parse_ts_param_strict("2026-01-31T00:00").has_value());
    CHECK_FALSE(parse_ts_param_strict("2028-02-30T00:00")); // 30 Feb never exists
    CHECK(parse_ts_param_strict("2026-02-28T00:00").has_value());
    CHECK(parse_ts_param_strict("2026-12-31T23:59:59").has_value());
    // Month 00 and 13 stay out of the day-length table; the lenient range check refuses them.
    CHECK_FALSE(parse_ts_param_strict("2026-00-31T00:00"));
    CHECK_FALSE(parse_ts_param_strict("2026-13-31T00:00"));
    // has_value() cannot see a roll-over, so pin the leap day to the day before March 1st.
    const auto leap_day = parse_ts_param_strict("2028-02-29T00:00");
    const auto march_first = parse_ts_param_strict("2028-03-01T00:00");
    REQUIRE(leap_day);
    REQUIRE(march_first);
    CHECK(*leap_day + 86400 == *march_first);
}

TEST_CASE("echo parse_ts_param_strict: every month accepts its last day and refuses the next",
          "[echo][tree][parse]") {
    constexpr int kLastDay[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}; // 2026
    const auto two = [](int n) { return std::string(n < 10 ? "0" : "") + std::to_string(n); };
    for (int m = 1; m <= 12; ++m) {
        const std::string ym = "2026-" + two(m) + "-";
        INFO("month " << m);
        CHECK(parse_ts_param_strict(ym + two(kLastDay[m - 1]) + "T00:00").has_value());
        CHECK_FALSE(parse_ts_param_strict(ym + two(kLastDay[m - 1] + 1) + "T00:00"));
    }
}

TEST_CASE("echo normalize_echo_os: maps to a closed audit-safe set", "[echo][tree][audit]") {
    CHECK(normalize_echo_os("Windows 11 Pro") == "windows");
    CHECK(normalize_echo_os("Microsoft Windows") == "windows");
    CHECK(normalize_echo_os("Ubuntu 22.04") == "linux");
    CHECK(normalize_echo_os("debian") == "linux");
    CHECK(normalize_echo_os("macOS 14") == "macos");
    CHECK(normalize_echo_os("Darwin") == "macos");
    CHECK(normalize_echo_os("") == "?");
    // An agent-controlled OS carrying structural delimiters can't escape the set.
    CHECK(normalize_echo_os("win\ndows evil=1") == "windows");
    CHECK(normalize_echo_os("totally unknown os") == "?");
}

// =============================================================================
// Device DNS / ARP panels (ADR-0015) — parsers + current-state reduction + escape

// =============================================================================
// Device DNS / ARP panels (ADR-0015) — hourly activity + escape
// =============================================================================

TEST_CASE("render_echo_dns_panel: only the selected hour, counts shown, fields escaped",
          "[echo][dns][panel]") {
    std::vector<EchoDnsHourRow> rows;
    EchoDnsHourRow a;
    a.hour_ts = 7200;
    a.name = "<b>evil</b>.test";
    a.record_type = "A";
    a.data = "1.1.1.1";
    a.appear_count = 14;
    a.remove_count = 13;
    a.negative_count = 2;
    rows.push_back(a);
    EchoDnsHourRow other = a;
    other.hour_ts = 3600;
    other.name = "older.test";
    rows.push_back(other);
    const auto html = render_echo_dns_panel(rows, 7200);
    CHECK(html.find("devnet-count\">1<") != std::string::npos);
    CHECK(html.find("&lt;b&gt;evil") != std::string::npos);
    CHECK(html.find("<b>evil") == std::string::npos);
    CHECK(html.find("older.test") == std::string::npos);
    CHECK(html.find("<th>No such name</th>") != std::string::npos);
    CHECK(html.find("<td>14</td><td>13</td><td>2</td>") != std::string::npos);
    CHECK(html.find("<th>TTL</th>") == std::string::npos);
    CHECK(html.find("<th>Src</th>") == std::string::npos);
    // An hour with no rows says so.
    const auto none = render_echo_dns_panel(rows, 9999);
    CHECK(none.find("devnet-count\">0<") != std::string::npos);
    CHECK(none.find("devnet-empty") != std::string::npos);
}

TEST_CASE("render_echo_arp_panel: counts, router role and rebinds for the selected hour",
          "[echo][arp][panel]") {
    EchoArpHourRow router;
    router.hour_ts = 7200;
    router.iface = "eth0";
    router.ip_address = "10.0.0.1";
    router.mac_address = "aa:bb:cc:dd:ee:ff";
    router.appear_count = 1;
    router.is_router = true;
    EchoArpHourRow rebound = router;
    rebound.ip_address = "10.0.0.7";
    rebound.is_router = false;
    rebound.rebind_count = 3;
    EchoArpHourRow older = router;
    older.hour_ts = 3600;
    older.ip_address = "10.9.9.9";
    const auto html = render_echo_arp_panel({router, rebound, older}, 7200);
    CHECK(html.find("devnet-count\">2<") != std::string::npos);
    CHECK(html.find("pill info\">router<") != std::string::npos);
    CHECK(html.find("3 MAC changes") != std::string::npos);
    CHECK(html.find("10.9.9.9") == std::string::npos);
    CHECK(html.find("<th>Type</th>") == std::string::npos);
    CHECK(render_echo_arp_panel({}, 7200).find("devnet-empty") != std::string::npos);
}

// =============================================================================
// Capture-source cards
// =============================================================================

namespace {
// One source's card: from its src-name span to the card's closing </dl></div>.
std::string card(const std::string& html, const std::string& name) {
    const auto b = html.find("<span class=\"src-name\">" + name + "</span>");
    REQUIRE(b != std::string::npos);
    return html.substr(b, html.find("</dl></div>", b) - b);
}
} // namespace

TEST_CASE("render_echo_capture_sources: cards, hourly names, staged toggles, device attr",
          "[echo][capture-sources]") {
    const std::string status =
        "config|process_enabled|true\nconfig|process_rows|18204\nconfig|process_oldest_ts|1760000400\n"
        "config|arp_enabled|false\nconfig|arp_rows|0\n"
        "config|dns_enabled|true\nconfig|dns_rows|42\n";
    const std::string html = render_echo_capture_sources("agent-123", status);
    CHECK(html.find("data-device=\"agent-123\"") != std::string::npos);
    CHECK(html.find("id=\"capCards\"") != std::string::npos);
    CHECK(html.find("<table") == std::string::npos);                 // cards, not a table
    CHECK(html.find("always on") != std::string::npos);             // process is locked
    CHECK(html.find("data-source=\"arp\"") != std::string::npos);   // arp is a staged toggle
    CHECK(html.find("badge-new") != std::string::npos);             // arp/dns NEW badge
    CHECK(html.find("stageCapToggle(this)") != std::string::npos);  // guardrail wiring
    CHECK(html.find("capApplyBar") != std::string::npos);           // push bar present
    CHECK(html.find("<dt>Hourly rows</dt>") != std::string::npos);
    CHECK(html.find("Live rows") == std::string::npos);
    CHECK(html.find("$Process_Hourly") != std::string::npos);
    CHECK(html.find("$DNS_Hourly") != std::string::npos);
    CHECK(html.find("$Process<") == std::string::npos);
    CHECK(html.find("OS support") == std::string::npos);
    // 1760000400 = 2025-10-09 09:00:00 UTC → shown as its bucket-resolution label.
    CHECK(card(html, "process").find("2025-10-09 09:00 UTC") != std::string::npos);
    CHECK(card(html, "process").find("Hourly</span><span>Daily</span><span>Monthly") != std::string::npos);
    CHECK(card(html, "dns").find("Hourly</span></dd>") != std::string::npos); // hourly only
}

TEST_CASE("render_echo_capture_sources: row count reads <src>_rows, then <src>_live_rows",
          "[echo][capture-sources]") {
    const auto rows_of = [](const std::string& status) {
        const std::string c = card(render_echo_capture_sources("d", status), "process");
        const auto b = c.find("<dt>Hourly rows</dt>");
        REQUIRE(b != std::string::npos);
        return c.substr(b, c.find("</dd>", b) - b);
    };
    // `_rows` alone.
    CHECK(rows_of("config|process_enabled|true\nconfig|process_rows|111\n").find(">111<") !=
          std::string::npos);
    // `_live_rows` alone (an agent that predates the rename).
    CHECK(rows_of("config|process_enabled|true\nconfig|process_live_rows|222\n").find(">222<") !=
          std::string::npos);
    // Both: `_rows` wins.
    const auto both = rows_of("config|process_enabled|true\nconfig|process_live_rows|222\nconfig|process_rows|111\n");
    CHECK(both.find(">111<") != std::string::npos);
    CHECK(both.find("222") == std::string::npos);
    // Neither: unknown is a dash, not a false zero.
    const auto none = rows_of("config|process_enabled|true\n");
    CHECK(none.find("&mdash;") != std::string::npos);
    CHECK(none.find(">0<") == std::string::npos);
}

TEST_CASE("render_echo_capture_sources: the registry source gets the System chip and a NEW badge",
          "[echo][capture-sources]") {
    const auto npos = std::string::npos;

    SECTION("reported by a Windows agent") {
        const std::string html = render_echo_capture_sources(
            "agent-123", "config|registry_enabled|true\nconfig|registry_rows|7\n");
        const auto c = card(html, "registry");
        CHECK(c.find("badge-new") != npos);
        CHECK(c.find("System") != npos);
        CHECK(c.find("$Registry_Hourly") != npos);
        CHECK(c.find("data-source=\"registry\"") != npos); // a staged toggle, not locked
        CHECK(html.find("data-cat=\"System\"") != npos);
        // the sixth chip, filtering to the System category
        CHECK(html.find("filterCap(this,'System')\">System</a>") != npos);
    }
    SECTION("an older agent that does not report registry_enabled: no card") {
        const std::string html = render_echo_capture_sources("agent-123", "config|process_enabled|true\n");
        CHECK(html.find("src-name\">registry<") == npos);
        CHECK(html.find("$Registry") == npos);
    }
}

TEST_CASE("render_echo_capture_sources: a paused core source reads paused with a locked unchecked box",
          "[echo][capture-sources]") {
    const std::string status =
        "config|process_enabled|true\nconfig|tcp_enabled|true\nconfig|service_enabled|false\n"
        "config|user_enabled|true\nconfig|perf_enabled|true\nconfig|arp_enabled|false\n"
        "config|service_paused_at|1760000400\n";
    const std::string html = render_echo_capture_sources("agent-123", status);
    const auto npos = std::string::npos;

    SECTION("core enabled") {
        const auto r = card(html, "process");
        CHECK(r.find("checked disabled") != npos);
        CHECK(r.find("state-on\">always on") != npos);
    }
    SECTION("core paused") {
        const auto r = card(html, "service");
        CHECK(r.find("tgl locked") != npos);
        CHECK(r.find("type=\"checkbox\" disabled>") != npos);
        CHECK(r.find("checked") == npos);
        CHECK(r.find("state-txt\">paused<") != npos);
        CHECK(r.find("since 2025-10-09T09:00:00Z") != npos);
        CHECK(r.find("always on") == npos);
        CHECK(r.find("data-source") == npos);
        CHECK(card(html, "tcp").find("always on") != npos);
    }
    SECTION("hostile device is escaped") {
        const std::string h = render_echo_capture_sources("a\"><script>", status);
        CHECK(h.find("data-device=\"a&quot;&gt;&lt;script&gt;\"") != npos);
        CHECK(h.find("<script>") == npos);
    }
}

TEST_CASE("render_echo_capture_sources: no sources reported says so", "[echo][capture-sources]") {
    const auto html = render_echo_capture_sources("d", "storage_state|ok\n");
    CHECK(html.find("No capture sources reported") != std::string::npos);
    CHECK(html.find("capApplyBar") == std::string::npos);
}

TEST_CASE("Echo page: the capture-sources push bar stays hidden until a change is staged",
          "[echo][capture-sources][page]") {
    // The renderer emits the bar with the `hidden` attribute; refreshCapBar() flips it.
    const std::string html = render_echo_capture_sources("agent-123", "config|arp_enabled|false\n");
    CHECK(html.find("id=\"capApplyBar\" hidden>") != std::string::npos);
    // `.apply-bar { display: flex }` outranks the UA `[hidden]` rule, so without this override
    // the bar is always visible ("0 pending changes").
    const std::string page = kEchoPageHtml;
    CHECK(page.find(".apply-bar[hidden] { display: none; }") != std::string::npos);
}

TEST_CASE("Echo renderers add no personal-data, privacy or usage-class wording to the UI",
          "[echo][render][copy]") {
    // Binding product rule: no such note, badge, pill, warning or caption is added to any
    // Echo UI string, and the old PII badge is not carried into the capture-source cards.
    EchoDnsHourRow d;
    d.hour_ts = 3600;
    d.name = "example.test";
    d.record_type = "A";
    EchoArpHourRow a;
    a.hour_ts = 3600;
    a.ip_address = "10.0.0.1";
    a.mac_address = "aa:bb";
    const auto tree = build_echo_process_tree({hr(3600, "bash", "", "alice", 1, 1, 1)}, 3600);
    const std::string all =
        render_echo_tree_fragment(tree, {conn(3600, "bash", "1.2.3.4", 443)}, kToken) +
        render_echo_proc_detail(tree.nodes[0], {conn(3600, "bash", "1.2.3.4", 443)}) +
        render_echo_dns_panel({d}, 3600) + render_echo_arp_panel({a}, 3600) +
        render_echo_dns_panel({}, 3600) + render_echo_arp_panel({}, 3600) +
        render_echo_capture_sources(
            "d", "config|process_enabled|true\nconfig|dns_enabled|true\nconfig|arp_enabled|true\n"
                 "config|registry_enabled|true\nconfig|service_enabled|false\n");
    const std::string text = lower(all);
    for (const char* banned : {"pii", "personal", "privacy", "sensitive", "usage-class", "usage class",
                               "gdpr", "badge-pii"})
        CHECK(text.find(banned) == std::string::npos);
}
