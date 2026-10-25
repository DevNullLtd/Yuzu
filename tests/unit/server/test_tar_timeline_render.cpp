/**
 * @file test_tar_timeline_render.cpp
 * @brief TAR timeline renderer: layout and collapse rules, the honesty copy,
 *        escaping, golden files under tests/unit/server/golden/tar-timeline/, and the
 *        `.tl-` CSS block pin.
 *
 * Pure: no store, no process, no file read except the golden files. Fixtures are synthetic
 * (a fixed one-hour window, names like proc-a.exe), not captures.
 *
 * Regeneration: `YUZU_UPDATE_GOLDEN=1 <server-tests> "[tar][timeline][golden]"` rewrites the
 * files and the run FAILS on purpose; re-run without the variable to confirm they match.
 */

#include "tar_timeline_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <regex>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace yuzu::server {
extern const std::string kYuzuCss; // server/core/static/yuzu.css (build-time embed)
} // namespace yuzu::server

namespace {

// 2026-10-20T09:00:00Z .. 10:00:00Z
constexpr std::int64_t W0 = 1792486800;
constexpr std::int64_t W1 = W0 + 3600;
constexpr std::int64_t kDay = 86400;

// ── golden helpers (the mechanism of test_access_golden.cpp) ───────────────────────

std::filesystem::path golden_dir() {
    return std::filesystem::path(YUZU_TEST_GOLDEN_DIR) / "tar-timeline";
}

void check_golden(const std::string& cell, const std::string& actual) {
    const auto path = golden_dir() / (cell + ".html");
    if (std::getenv("YUZU_UPDATE_GOLDEN") != nullptr) {
        std::error_code ec;
        std::filesystem::create_directories(golden_dir(), ec);
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        REQUIRE(out.good());
        out << actual;
        out.close();
        REQUIRE(out.good());
        FAIL_CHECK("YUZU_UPDATE_GOLDEN=1: (re)wrote " << path.string()
                   << " -- re-run WITHOUT YUZU_UPDATE_GOLDEN to verify it now matches.");
        return;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in.good()) {
        FAIL_CHECK("golden file missing: " << path.string()
                   << " -- run with YUZU_UPDATE_GOLDEN=1 to create it, then re-run to verify.");
        return;
    }
    const std::string expected((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    INFO("golden mismatch for '" << cell << "' (" << path.string() << ")");
    CHECK(expected == actual);
}

std::string escaped(const std::string& raw) {
    std::string out;
    for (char c : raw)
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    return out;
}

void contains(const std::string& html, const std::string& needle) {
    INFO("expected to find: " << needle);
    CHECK(html.find(needle) != std::string::npos);
}

void lacks(const std::string& html, const std::string& needle) {
    INFO("expected NOT to find: " << needle);
    CHECK(html.find(needle) == std::string::npos);
}

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

// ── fixture builders ───────────────────────────────────────────────────────────────

TarTimelineRegion region(TarRegionKind k, std::int64_t a = W0, std::int64_t b = W1) {
    TarTimelineRegion r;
    r.kind = k;
    r.from_ts = a;
    r.to_ts = b;
    return r;
}
TarTimelineRegion rolled(TarTier t, std::int64_t a = W0, std::int64_t b = W1) {
    auto r = region(TarRegionKind::rolled_up, a, b);
    r.tier = t;
    return r;
}
TarTimelineRegion unreadable(TarUnreadableReason why, std::int64_t a = W0, std::int64_t b = W1) {
    auto r = region(TarRegionKind::not_readable, a, b);
    r.reason = why;
    return r;
}
TarTimelineRegion capped(std::int64_t a, std::int64_t b, std::int64_t rows, std::int64_t from) {
    auto r = region(TarRegionKind::capped, a, b);
    r.cap_rows = rows;
    r.coverage_from_ts = from;
    return r;
}
TarTimelineRegion paused(std::int64_t a, std::int64_t b, std::int64_t since) {
    auto r = region(TarRegionKind::paused, a, b);
    r.paused_since_ts = since;
    return r;
}

TarTimelineItem bar(const std::string& id, std::int64_t from, std::int64_t to,
                    const std::string& label = {}) {
    TarTimelineItem i;
    i.id = id;
    i.shape = TarItemShape::bar;
    i.from_ts = from;
    i.to_ts = to;
    i.label = label.empty() ? id : label;
    return i;
}
TarTimelineItem tick(const std::string& id, std::int64_t at, const std::string& label = {}) {
    auto i = bar(id, at, 0, label);
    i.shape = TarItemShape::tick;
    return i;
}
TarTimelineItem bucket(const std::string& id, std::int64_t from, std::int64_t to,
                       std::int64_t count, TarTier tier = TarTier::hourly) {
    auto i = bar(id, from, to, std::to_string(count));
    i.shape = TarItemShape::count;
    i.count = count;
    i.tier = tier;
    return i;
}
TarTimelineItem column(const std::string& id, std::int64_t from, std::int64_t to,
                       std::int64_t value, TarTier tier = TarTier::exact) {
    auto i = bar(id, from, to, std::to_string(value) + "%");
    i.shape = TarItemShape::column;
    i.count = value;
    i.tier = tier;
    return i;
}

TarTimelineLane lane(const std::string& id, const std::string& source, const std::string& name,
                     std::vector<TarTimelineItem> items = {},
                     std::vector<TarTimelineRegion> regions = {region(TarRegionKind::exact)}) {
    TarTimelineLane l;
    l.id = id;
    l.source = source;
    l.name = name;
    l.items = std::move(items);
    l.regions = std::move(regions);
    return l;
}

TarKeptBand band(TarTier t, std::int64_t oldest, std::int64_t policy_s = 0) {
    return {t, oldest, policy_s};
}

TarKeptRow kept(const std::string& source, const std::string& label, std::int64_t row_limit,
                std::vector<TarKeptBand> bands, std::int64_t paused_since = 0) {
    TarKeptRow r;
    r.source = source;
    r.label = label;
    r.row_limit = row_limit;
    r.bands = std::move(bands);
    r.paused_since_ts = paused_since;
    return r;
}

TarTimelineModel base() {
    TarTimelineModel m;
    m.agent_id = "agent-1";
    m.hostname = "host-a";
    m.os = "Windows 11";
    m.online = true;
    m.read_ts = W1;
    m.window_from_ts = W0;
    m.window_to_ts = W1;
    m.moment_ts = W0 + 1800;
    m.poll_interval_s = 60;
    m.process_capture_method = "etw";
    const std::pair<const char*, const char*> kSources[] = {{"process", "Processes"},
                                                              {"tcp", "Network connections"},
                                                              {"dns", "DNS cache"},
                                                              {"arp", "ARP neighbours"},
                                                              {"service", "Services"},
                                                              {"user", "Sessions"},
                                                              {"perf", "Performance"}};
    for (const auto& [src, label] : kSources) {
        TarSourceState st;
        st.source = src;
        st.label = label;
        m.sources.push_back(st);
    }
    // Row-limited exact tier (process), and a time-limited ladder (arp).
    m.kept.push_back(kept("process", "Processes", 100000,
                          {band(TarTier::exact, W1 - 2 * kDay), band(TarTier::hourly, W1 - 20 * kDay, 20 * kDay),
                           band(TarTier::daily, W1 - 90 * kDay, 90 * kDay)}));
    m.kept.push_back(kept("arp", "ARP neighbours", 0,
                          {band(TarTier::exact, W1 - kDay, kDay), band(TarTier::hourly, W1 - 10 * kDay, 10 * kDay),
                           band(TarTier::daily, W1 - 31 * kDay, 31 * kDay)}));
    m.kept.push_back(kept("service", "Services", 20000,
                          {band(TarTier::exact, W1 - 25 * kDay), band(TarTier::hourly, 0)}, W1 - 20 * kDay));

    auto p1 = bar("P1", W0 + 600, W0 + 2400, "proc-a.exe 4120");
    p1.facts = {{"Started by", "proc-b.exe 100"}, {"User", "s.user"}};
    auto p2 = bar("P2", W0 + 3000, 0, "proc-b.exe 7210");
    p2.flagged = true;
    p2.linked_ids = {"P1", "gone-id"};
    auto k2 = column("K2", W0 + 1830, W0 + 1860, 90);
    k2.flagged = true;
    TarTimelineGroup procs{"Processes",
                           {lane("L-pa", "process", "proc-a.exe", {p1}),
                            [&] {
                                auto l = lane("L-pb", "process", "proc-b.exe", {p2});
                                l.depth = 1;
                                return l;
                            }()}};
    TarTimelineGroup net{"Network",
                         {lane("L-tcp", "tcp", "TCP connections", {bar("C1", W0 + 1200, W0 + 1500, "203.0.113.9:443")}),
                          lane("L-dns", "dns", "DNS cache", {tick("D1", W0 + 1500, "files.example.net")}),
                          lane("L-arp", "arp", "ARP neighbours", {tick("A1", W0 + 100, "192.0.2.7")})}};
    TarTimelineGroup sys{"System",
                         {lane("L-svc", "service", "Service changes", {tick("S1", W0 + 2000, "Spooler stopped")}),
                          lane("L-usr", "user", "Sessions", {bar("U1", W0, 0, "s.user")}),
                          lane("L-perf", "perf", "CPU", {column("K1", W0 + 1800, W0 + 1830, 42), k2})}};
    m.groups = {procs, net, sys};
    return m;
}

TarTimelineModel with_lane(TarTimelineLane l, const std::string& group = "Group") {
    auto m = base();
    m.groups = {TarTimelineGroup{group, {std::move(l)}}};
    return m;
}

TarTimelineLinks links_full() {
    TarTimelineLinks l;
    l.moment = [](std::int64_t t) { return "/tar/moment?t=" + std::to_string(t); };
    l.selected = [](const std::string& id, std::int64_t t) {
        return "/tar/selected?ref=" + id + "&t=" + std::to_string(t);
    };
    l.device = "/device?id=agent-1";
    l.choose_device = "/devices";
    l.retention_paused = "/tar#paused";
    return l;
}

/// A model for the kept chart: a 60-day window so a moment can sit in an older tier.
TarTimelineModel kept_model(std::int64_t moment_age_s) {
    auto m = base();
    m.window_from_ts = W1 - 60 * kDay;
    m.moment_ts = W1 - moment_age_s;
    return m;
}

double ax(std::int64_t age) {
    return std::log1p(static_cast<double>(age) / 3600.0) / std::log1p(480.0 * 86400.0 / 3600.0) * 100.0;
}

std::string pct3(double v) { return std::format("{:.3f}", v); }

/// The `.tl-kr` row of one source in the kept chart.
std::string kept_row_html(const std::string& html, const std::string& source) {
    const std::string key = "data-source=\"" + source + "\"";
    const auto a = html.find("<div class=\"tl-kr\" " + key);
    REQUIRE(a != std::string::npos);
    const auto b = html.find("<div class=\"tl-kr\"", a + 10);
    return html.substr(a, b == std::string::npos ? std::string::npos : b - a);
}

std::vector<std::string> all_outputs(const TarTimelineModel& m, const TarTimelineLinks& l,
                                     const std::string& ref = "P1") {
    const auto t = tar_timeline_resolve_moment(m);
    return {render_timeline_device_bar(m, l), render_timeline_kept(m), render_timeline_lanes(m),
            render_timeline_limits(m, l),     render_timeline_moment(m, t, l),
            render_timeline_selected(m, ref, t, l)};
}

} // namespace

// ═══ layout ═══════════════════════════════════════════════════════════════════════════

TEST_CASE("tar timeline layout: percent clamps, degenerate window is safe, three decimals",
          "[tar][timeline]") {
    auto m = base();
    CHECK(tar_timeline_pct(m, W0 - 500) == 0.0);
    CHECK(tar_timeline_pct(m, W1 + 500) == 100.0);
    CHECK(tar_timeline_pct(m, W0 + 1800) == 50.0);
    m.window_to_ts = m.window_from_ts;
    CHECK(tar_timeline_pct(m, W0 + 5) == 0.0);
    CHECK(tar_timeline_layout_lane(lane("l", "process", "p", {bar("a", W0, W0 + 10)}), m).blocks.empty());
    m = base();
    const auto lay = tar_timeline_layout_lane(lane("l", "process", "p", {bar("a", W0 + 1, W0 + 1801)}), m);
    REQUIRE(lay.blocks.size() == 1);
    CHECK(pct3(lay.blocks[0].left_pct) == "0.028");
    contains(render_timeline_lanes(with_lane(lane("l", "process", "p", {bar("a", W0 + 1, W0 + 1801)}))),
             "left:0.028%;width:50.000%");
}

TEST_CASE("tar timeline layout: open bars run to the window end with .cr, early starts carry .cl",
          "[tar][timeline]") {
    auto m = base();
    const auto lay = tar_timeline_layout_lane(
        lane("l", "process", "p", {bar("open", W0 + 1800, 0), bar("early", W0 - 600, W0 + 600)}), m);
    REQUIRE(lay.blocks.size() == 2);
    // sorted by start: "early" first
    CHECK(lay.blocks[0].id == "early");
    CHECK(lay.blocks[0].cls.find(" cl") != std::string::npos);
    CHECK(lay.blocks[0].cls.find(" cr") == std::string::npos);
    CHECK(lay.blocks[1].id == "open");
    CHECK(lay.blocks[1].cls.find(" cr") != std::string::npos);
    CHECK(lay.blocks[1].left_pct + lay.blocks[1].width_pct == 100.0);
}

TEST_CASE("tar timeline layout: items outside the window are ignored", "[tar][timeline]") {
    auto m = base();
    const auto lay = tar_timeline_layout_lane(
        lane("l", "process", "p",
             {bar("before", W0 - 900, W0 - 100), bar("after", W1 + 10, W1 + 900), tick("t-after", W1 + 1)}),
        m);
    CHECK(lay.blocks.empty());
}

TEST_CASE("tar timeline layout: a one-second item keeps the width floor; the time chips flip at the edges",
          "[tar][timeline]") {
    // 1 s of a one-hour window is 0.028%: it draws at the 0.250% floor
    contains(render_timeline_lanes(with_lane(lane("l", "process", "p", {bar("a", W0 + 600, W0 + 601)}))),
             "width:0.250%");
    // the moment chip sits on the side it would otherwise overflow
    auto m = with_lane(lane("l", "process", "p"));
    m.moment_ts = W0 + 60;
    const auto start = render_timeline_lanes(m);
    contains(start, "<b class=\"s\">");
    lacks(start, "<b class=\"e\">");
    m.moment_ts = W1 - 60;
    const auto end = render_timeline_lanes(m);
    contains(end, "<b class=\"e\">");
    lacks(end, "<b class=\"s\">");
    m.moment_ts = W0 + 1800;
    const auto mid = render_timeline_lanes(m);
    lacks(mid, "<b class=\"s\">");
    lacks(mid, "<b class=\"e\">");
    // the kept-chart marker chip right-aligns once it is past 55% of the age axis
    contains(render_timeline_kept(kept_model(15 * kDay)), "<b class=\"r\">");
    lacks(render_timeline_kept(kept_model(3600)), "<b class=\"r\">");
}

TEST_CASE("tar timeline collapse: bars collapse at eight, exact count, never 'about'",
          "[tar][timeline]") {
    auto m = base();
    std::vector<TarTimelineItem> seven, many;
    for (int i = 0; i < 7; ++i)
        seven.push_back(bar("s" + std::to_string(i), W0 + i * 12, W0 + i * 12 + 1));
    CHECK(tar_timeline_layout_lane(lane("l", "process", "p", seven), m).blocks.size() == 7);

    // exactly eight is the threshold: one more tiny bar and the run collapses
    std::vector<TarTimelineItem> eight = seven;
    eight.push_back(bar("s7", W0 + 7 * 12, W0 + 7 * 12 + 1));
    const auto e = tar_timeline_layout_lane(lane("l", "process", "p", eight), m);
    REQUIRE(e.blocks.size() == 1);
    CHECK(e.blocks[0].collapsed);
    CHECK(e.blocks[0].label == "8 events");

    for (int i = 0; i < 300; ++i)
        many.push_back(bar("m" + std::to_string(i), W0 + i * 12, W0 + i * 12 + 1));
    const auto lay = tar_timeline_layout_lane(lane("l", "process", "p", many), m);
    std::int64_t total = 0;
    for (const auto& b : lay.blocks)
        total += b.collapsed ? b.count : 1;
    CHECK(total == 300);
    REQUIRE(!lay.blocks.empty());
    CHECK(lay.blocks[0].collapsed);
    CHECK(lay.blocks[0].label == "300 events");
    for (const auto& b : lay.blocks)
        CHECK(b.label.find("about") == std::string::npos);
}

TEST_CASE("tar timeline collapse: buckets say buckets and events, samples say samples",
          "[tar][timeline]") {
    auto m = base();
    std::vector<TarTimelineItem> buckets, cols;
    for (int i = 0; i < 8; ++i) {
        buckets.push_back(bucket("b" + std::to_string(i), W0 + i * 20, W0 + i * 20 + 20, 50));
        cols.push_back(column("c" + std::to_string(i), W0 + i * 20, W0 + i * 20 + 20, 10 + i));
    }
    const auto b = tar_timeline_layout_lane(lane("l", "dns", "d", buckets), m);
    REQUIRE(b.blocks.size() == 1);
    CHECK(b.blocks[0].label == "8 buckets, 400 events");
    const auto c = tar_timeline_layout_lane(lane("l", "perf", "p", cols), m);
    REQUIRE(c.blocks.size() == 1);
    CHECK(c.blocks[0].label == "8 samples");
}

TEST_CASE("tar timeline collapse: a shape change ends the run", "[tar][timeline]") {
    auto m = base();
    std::vector<TarTimelineItem> mixed;
    for (int i = 0; i < 4; ++i)
        mixed.push_back(bar("b" + std::to_string(i), W0 + i * 12, W0 + i * 12 + 1));
    for (int i = 4; i < 8; ++i)
        mixed.push_back(tick("t" + std::to_string(i), W0 + i * 12));
    const auto lay = tar_timeline_layout_lane(lane("l", "process", "p", mixed), m);
    CHECK(lay.blocks.size() == 8);
    for (const auto& b : lay.blocks)
        CHECK_FALSE(b.collapsed);
}

TEST_CASE("tar timeline collapse: only a contiguous run collapses", "[tar][timeline]") {
    auto m = base();
    // One-second bars, one every 12 s (a 0.3% gap, under the 0.6% block width); `extra_s` more
    // seconds of silence open before item `gap_at`.
    auto train = [](int n, int gap_at, int extra_s) {
        std::vector<TarTimelineItem> v;
        std::int64_t t = W0;
        for (int i = 0; i < n; ++i) {
            if (i == gap_at)
                t += extra_s;
            v.push_back(bar("g" + std::to_string(i), t, t + 1));
            t += 12;
        }
        return v;
    };
    // nine contiguous: one block
    auto lay = tar_timeline_layout_lane(lane("l", "process", "p", train(9, -1, 0)), m);
    REQUIRE(lay.blocks.size() == 1);
    CHECK(lay.blocks[0].collapsed);
    CHECK(lay.blocks[0].label == "9 events");
    // the same nine with a 1.1% gap before the fifth: two runs, each under eight, nothing collapses
    lay = tar_timeline_layout_lane(lane("l", "process", "p", train(9, 4, 30)), m);
    CHECK(lay.blocks.size() == 9);
    for (const auto& b : lay.blocks)
        CHECK_FALSE(b.collapsed);
    // sixteen with that gap in the middle: two collapsed runs of eight, never one of sixteen
    lay = tar_timeline_layout_lane(lane("l", "process", "p", train(16, 8, 30)), m);
    REQUIRE(lay.blocks.size() == 2);
    CHECK(lay.blocks[0].label == "8 events");
    CHECK(lay.blocks[1].label == "8 events");
}

TEST_CASE("tar timeline collapse: wide items never collapse; the per-lane cap counts the rest",
          "[tar][timeline]") {
    auto m = base();
    std::vector<TarTimelineItem> wide;
    for (int i = 0; i < 405; ++i) // 600 s wide (16.7%), one starting every 8 s
        wide.push_back(bar("w" + std::to_string(i), W0 + i * 8, W0 + i * 8 + 600));
    const auto lay = tar_timeline_layout_lane(lane("l", "process", "p", wide), m);
    CHECK(lay.blocks.size() == kTarTimelineMaxBlocksPerLane);
    CHECK(lay.overflow_count == 5);
    const auto html = render_timeline_lanes(with_lane(lane("l", "process", "p", wide)));
    CHECK(count_of(html, "<button type=\"button\" class=\"tl-b") == 400);
    contains(html, "5 more items, not drawn");
    contains(html, "render limit");
    // the boundary: 399 and 400 blocks draw in full, 401 counts one and says so
    for (const int n : {399, 400, 401}) {
        INFO("blocks: " << n);
        std::vector<TarTimelineItem> v(wide.begin(), wide.begin() + n);
        const auto lb = tar_timeline_layout_lane(lane("l", "process", "p", v), m);
        CHECK(lb.blocks.size() == static_cast<std::size_t>(std::min(n, 400)));
        CHECK(lb.overflow_count == static_cast<std::size_t>(n > 400 ? n - 400 : 0));
        const auto page = render_timeline_lanes(with_lane(lane("l", "process", "p", v)));
        CHECK((page.find("not drawn") != std::string::npos) == (n > 400));
        CHECK((page.find("render limit") != std::string::npos) == (n > 400));
    }
    // under the cap: no note, no banner
    lacks(render_timeline_lanes(base()), "not drawn");
    lacks(render_timeline_lanes(base()), "render limit");
}

TEST_CASE("tar timeline region_at: boundaries, last region closed, a gap is nullptr",
          "[tar][timeline]") {
    const auto l = lane("l", "process", "p", {},
                        {region(TarRegionKind::exact, W0, W0 + 1000),
                         region(TarRegionKind::pruned, W0 + 1000, W0 + 2000)});
    auto kind_at = [&](std::int64_t t) {
        const auto* r = tar_timeline_region_at(l, t);
        REQUIRE(r != nullptr);
        return r->kind;
    };
    CHECK(kind_at(W0) == TarRegionKind::exact);
    CHECK(kind_at(W0 + 999) == TarRegionKind::exact);
    CHECK(kind_at(W0 + 1000) == TarRegionKind::pruned);
    CHECK(kind_at(W0 + 2000) == TarRegionKind::pruned); // closed at the end
    CHECK(tar_timeline_region_at(l, W0 + 2001) == nullptr);
    CHECK(tar_timeline_region_at(l, W0 - 1) == nullptr);

    // a stretch with no region reads "Coverage not stated", never exact
    const auto html = render_timeline_lanes(with_lane(lane("l", "process", "p", {}, {})));
    contains(html, "tl-rg unstated");
    contains(html, "Coverage not stated");
    lacks(html, "Exact");
}

TEST_CASE("tar timeline items_at: membership is by shape", "[tar][timeline]") {
    const auto l = lane("l", "process", "p",
                        {bar("alive", W0 + 100, W0 + 200), bar("open", W0 + 150, 0),
                         tick("t-before", W0 + 120), tick("t-at", W0 + 180), tick("t-after", W0 + 190),
                         bucket("bk", W0 + 100, W0 + 180, 3), column("col", W0 + 180, W0 + 210, 5)});
    auto ids = [](const std::vector<const TarTimelineItem*>& v) {
        std::vector<std::string> out;
        for (const auto* i : v)
            out.push_back(i->id);
        return out;
    };
    // at 180: bar alive (100<=180<200), open, both ticks at or before 180 (newest first),
    // the bucket ended at 180 (excluded: from<=t<to), the column starts at 180 (included).
    CHECK(ids(tar_timeline_items_at(l, W0 + 180)) ==
          std::vector<std::string>{"alive", "open", "col", "t-at", "t-before"});
    // an alive bar excludes t == to
    CHECK(ids(tar_timeline_items_at(l, W0 + 200)) == std::vector<std::string>{"open", "col", "t-after", "t-at", "t-before"});
    // a tick after t is excluded
    CHECK(ids(tar_timeline_items_at(l, W0 + 100)) == std::vector<std::string>{"alive", "bk"});
}

TEST_CASE("tar timeline adjacent_events: bars and ticks only, 0 disables", "[tar][timeline]") {
    auto m = with_lane(lane("l", "process", "p",
                            {bar("b", W0 + 600, W0 + 1200), tick("t", W0 + 2000),
                             bucket("bk", W0 + 900, W0 + 960, 2), column("c", W0 + 1500, W0 + 1530, 9)}));
    auto adj = tar_timeline_adjacent_events(m, W0 + 1000);
    CHECK(adj.prev == W0 + 600);
    CHECK(adj.next == W0 + 1200);
    adj = tar_timeline_adjacent_events(m, W0 + 1300);
    CHECK(adj.prev == W0 + 1200);
    CHECK(adj.next == W0 + 2000); // the bucket and the column are not events
    CHECK(tar_timeline_adjacent_events(m, W0 + 300).prev == 0);
    CHECK(tar_timeline_adjacent_events(m, W0 + 2500).next == 0);
}

TEST_CASE("tar timeline resolve_moment: inside the window, newest boundary, window end",
          "[tar][timeline]") {
    auto m = base();
    m.moment_ts = W0 + 77;
    CHECK(tar_timeline_resolve_moment(m) == W0 + 77);
    m.moment_ts = 0;
    CHECK(tar_timeline_resolve_moment(m) == W0 + 3000); // P2 starts at W0+3000: the newest boundary
    m.moment_ts = W1 + 100; // outside: falls back
    CHECK(tar_timeline_resolve_moment(m) == W0 + 3000);
    m.groups.clear();
    CHECK(tar_timeline_resolve_moment(m) == W1);
}

namespace {
std::vector<std::string> ruler_labels(const std::string& html) {
    static const std::regex re("<span class=\"tl-tk\" style=\"left:[0-9.]+%\">([^<]*)</span>");
    std::vector<std::string> out;
    for (std::sregex_iterator it(html.begin(), html.end(), re), end; it != end; ++it)
        out.push_back((*it)[1].str());
    return out;
}
} // namespace

TEST_CASE("tar timeline ruler: one window per tick step, exact labels, UTC named once",
          "[tar][timeline]") {
    struct Row {
        const char* name;
        std::int64_t from, span;
        std::size_t ticks;
        std::vector<std::string> first;
    };
    const std::int64_t d20_20h = W0 + 11 * 3600; // 2026-10-20T20:00:00Z
    const std::int64_t nov15 = 1794700800;       // 2026-11-15T00:00:00Z
    const Row rows[] = {
        {"60 s step, up to 30 minutes", W0, 1200, 21, {"09:00", "09:01"}},
        {"60 s step, a full 30-minute window", W0, 1800, 31, {"09:00", "09:01"}},
        {"5 min step, up to 6 hours", W0, 3 * 3600, 37, {"09:00", "09:05"}},
        {"2 h step, a midnight tick is a date", d20_20h, 2 * kDay, 25, {"20:00", "22:00", "21 Oct"}},
        {"daily step, up to 14 days", W0, 7 * kDay, 7, {"Wed 21", "Thu 22"}},
        {"3 day step, up to 90 days", W0, 30 * kDay, 10, {"22 Oct", "25 Oct"}},
        {"month boundaries, a January names its year", nov15, 120 * kDay, 4,
         {"Dec", "Jan 2027", "Feb", "Mar"}},
    };
    for (const auto& r : rows) {
        INFO(r.name);
        auto m = base();
        m.window_from_ts = r.from;
        m.window_to_ts = r.from + r.span;
        m.moment_ts = r.from + r.span / 2;
        const auto html = render_timeline_lanes(m);
        CHECK(count_of(html, "Time (UTC)") == 1);
        const auto labels = ruler_labels(html);
        CHECK(labels.size() == r.ticks);
        for (std::size_t i = 0; i < r.first.size() && i < labels.size(); ++i)
            CHECK(labels[i] == r.first[i]);
    }
    // the month ruler is bounded: a window past two years draws its first 24 months, no more
    auto long_window = base();
    long_window.window_from_ts = nov15;
    long_window.window_to_ts = nov15 + 1100 * kDay;
    long_window.moment_ts = nov15 + kDay;
    CHECK(ruler_labels(render_timeline_lanes(long_window)).size() <= 24);
}

// ═══ goldens: lanes ═══════════════════════════════════════════════════════════════════

TEST_CASE("tar timeline golden: lanes online", "[tar][timeline][golden]") {
    const auto html = render_timeline_lanes(base());
    check_golden("lanes__online", html);
    CHECK(count_of(html, "Time (UTC)") == 1);
    CHECK(count_of(html, "UTC") == 1);
    contains(html, "tl-ph");
    contains(html, "tl-fut");
    contains(html, "class=\"tl-row d1\""); // depth ladder, never inline style
    contains(html, "tl-b bad");
    lacks(html, "tl-warn");
}

TEST_CASE("tar timeline golden: lanes offline", "[tar][timeline][golden]") {
    auto m = base();
    m.online = false;
    for (auto& g : m.groups)
        for (auto& l : g.lanes)
            l.regions = {unreadable(TarUnreadableReason::offline)};
    const auto html = render_timeline_lanes(m);
    check_golden("lanes__offline", html);
    contains(html, "Not readable: device offline");
    contains(html, "Device offline: on-device records are not readable.");
    CHECK(count_of(html, "tl-warn") == 1); // the device banner says it once; no per-lane repeat
    lacks(html, "Exact");
}

TEST_CASE("tar timeline golden: lanes read failed", "[tar][timeline][golden]") {
    auto m = base();
    m.groups[1].lanes[0].regions = {unreadable(TarUnreadableReason::read_failed)};
    const auto html = render_timeline_lanes(m);
    check_golden("lanes__read-failed", html);
    contains(html, "Not readable: the read failed");
    // an online read that failed is said before the chart, naming the lane
    const std::string warn =
        "<div class=\"tl-warn\">TCP connections could not be read: the read failed.</div>";
    contains(html, warn);
    CHECK(html.find(warn) < html.find("<div class=\"tl\">"));
}

TEST_CASE("tar timeline golden: lanes agent too old", "[tar][timeline][golden]") {
    auto m = base();
    m.groups[2].lanes[2].regions = {unreadable(TarUnreadableReason::agent_too_old)};
    const auto html = render_timeline_lanes(m);
    check_golden("lanes__agent-too-old", html);
    contains(html, "Not readable: the agent is too old for this read");
    const std::string warn = "<div class=\"tl-warn\">CPU could not be read: the agent is too old for "
                             "this read.</div>";
    contains(html, warn);
    CHECK(html.find(warn) < html.find("<div class=\"tl\">"));
}

TEST_CASE("tar timeline banners: one per distinct lane and reason, offline not repeated per lane",
          "[tar][timeline]") {
    // two unreadable stretches of one lane with one reason: one banner
    auto m = with_lane(lane("l", "tcp", "TCP connections", {},
                            {unreadable(TarUnreadableReason::read_failed, W0, W0 + 600),
                             region(TarRegionKind::exact, W0 + 600, W0 + 1800),
                             unreadable(TarUnreadableReason::read_failed, W0 + 1800, W0 + 3000)}));
    CHECK(count_of(render_timeline_lanes(m), "could not be read") == 1);
    // a second reason on the same lane is its own banner
    m.groups[0].lanes[0].regions.push_back(unreadable(TarUnreadableReason::agent_too_old, W0 + 3000, W1));
    CHECK(count_of(render_timeline_lanes(m), "could not be read") == 2);
    // a second lane with the same reason is its own banner
    m.groups[0].lanes.push_back(lane("l2", "dns", "DNS cache", {}, {unreadable(TarUnreadableReason::read_failed)}));
    CHECK(count_of(render_timeline_lanes(m), "could not be read: the read failed") == 2);
    // reason "offline" on an ONLINE model has no device banner above it, so the lane says it
    auto on = with_lane(lane("l", "tcp", "TCP connections", {}, {unreadable(TarUnreadableReason::offline)}));
    contains(render_timeline_lanes(on), "TCP connections could not be read: device offline.");
}

TEST_CASE("tar timeline capped: stretches of one lane are one banner and one limits bullet",
          "[tar][timeline]") {
    // two adjacent, non-overlapping capped stretches of one lane, and a second capped lane
    auto m = with_lane(lane("L-p", "process", "proc-a.exe", {},
                            {capped(W0, W0 + 1200, 10000, W0 + 1200),
                             capped(W0 + 1200, W0 + 2400, 10000, W0 + 1500),
                             region(TarRegionKind::exact, W0 + 2400, W1)}));
    m.groups[0].lanes.push_back(
        lane("L-t", "tcp", "TCP connections", {}, {capped(W0, W1, 5000, W0 + 3000)}));
    const std::string first = "The read of proc-a.exe was cut off at 10000 rows; nothing before "
                              "2026-10-20T09:20:00Z is shown.";
    const auto lanes = render_timeline_lanes(m);
    CHECK(count_of(lanes, "tl-warn") == 2); // one per capped lane
    contains(lanes, "<div class=\"tl-warn\">" + first + "</div>");
    contains(lanes, "<div class=\"tl-warn\">The read of TCP connections was cut off at 5000 rows; "
                    "nothing before 2026-10-20T09:50:00Z is shown.</div>");
    lacks(lanes, "nothing before 2026-10-20T09:25:00Z"); // the later stretch is not a second claim
    CHECK(count_of(lanes, "tl-rg capped") == 3);         // every stretch still draws its own region
    const auto limits = render_timeline_limits(m, links_full());
    CHECK(count_of(limits, "was cut off") == 2);
    contains(limits, "<li>" + first + "</li>");
    lacks(limits, "nothing before 2026-10-20T09:25:00Z");
}

TEST_CASE("tar timeline golden: lanes paused", "[tar][timeline][golden]") {
    auto m = base();
    m.groups[2].lanes[0].regions = {region(TarRegionKind::exact, W0, W0 + 1800),
                                    paused(W0 + 1800, W1, W0 + 1800)};
    const auto html = render_timeline_lanes(m);
    check_golden("lanes__paused", html);
    contains(html, "Paused since 2026-10-20T09:30:00Z");
    contains(html, "tl-rg paused");
}

TEST_CASE("tar timeline paused: an unreported pause time is said in words, never a dash",
          "[tar][timeline]") {
    // a pre-0.12.0 agent reports a disabled source with a pause time of 0
    auto m = with_lane(lane("L-svc", "service", "Service changes", {},
                            {region(TarRegionKind::exact, W0, W0 + 1800), paused(W0 + 1800, W1, 0)}));
    const auto lanes = render_timeline_lanes(m);
    contains(lanes, "<b>Paused since a time the agent did not report</b>");
    lacks(lanes, "Paused since 20"); // no date
    lacks(lanes, "\xE2\x80\x94");   // the em dash format_iso_utc gives a zero time
    const auto moment = render_timeline_moment(m, W0 + 2000, links_full());
    contains(moment, "Service changes: Not recorded since a time the agent did not report");
    lacks(moment, "\xE2\x80\x94");
    // a known pause time still names it
    m.groups[0].lanes[0].regions = {region(TarRegionKind::exact, W0, W0 + 1800),
                                    paused(W0 + 1800, W1, W0 + 1800)};
    contains(render_timeline_lanes(m), "<b>Paused since 2026-10-20T09:30:00Z</b>");
}

TEST_CASE("tar timeline golden: lanes pruned", "[tar][timeline][golden]") {
    auto m = base();
    m.groups[1].lanes[1].regions = {region(TarRegionKind::pruned, W0, W0 + 1800),
                                    region(TarRegionKind::exact, W0 + 1800, W1)};
    const auto html = render_timeline_lanes(m);
    check_golden("lanes__pruned", html);
    contains(html, "tl-rg pruned");
    contains(html, "<b>Pruned</b>");
}

TEST_CASE("tar timeline golden: lanes capped", "[tar][timeline][golden]") {
    auto m = base();
    m.groups[0].lanes[0].regions = {capped(W0, W0 + 1800, 10000, W0 + 1800),
                                    region(TarRegionKind::exact, W0 + 1800, W1)};
    const auto html = render_timeline_lanes(m);
    check_golden("lanes__capped", html);
    contains(html, "Record cut off at 10000 rows; showing from 2026-10-20T09:30:00Z");
    contains(html, "The read of proc-a.exe was cut off at 10000 rows; nothing before "
                   "2026-10-20T09:30:00Z is shown.");
}

TEST_CASE("tar timeline golden: lanes rolled up", "[tar][timeline][golden]") {
    auto m = with_lane(lane("L-dns", "dns", "DNS cache", {bucket("B1", W0, W1, 14)},
                            {rolled(TarTier::hourly)}));
    const auto html = render_timeline_lanes(m);
    check_golden("lanes__rolled-up", html);
    contains(html, "Hourly roll-up");
    contains(html, "tl-rg rolled");
}

TEST_CASE("tar timeline golden: lanes dense collapse", "[tar][timeline][golden]") {
    std::vector<TarTimelineItem> many;
    for (int i = 0; i < 300; ++i)
        many.push_back(bar("m" + std::to_string(i), W0 + i * 12, W0 + i * 12 + 1));
    const auto html = render_timeline_lanes(with_lane(lane("L-busy", "process", "busy.exe", many)));
    check_golden("lanes__dense-collapse", html);
    contains(html, "300 events");
    CHECK(html.size() < 8000); // collapsed: not 300 buttons
}

TEST_CASE("tar timeline golden: lanes dense collapse of counts", "[tar][timeline][golden]") {
    std::vector<TarTimelineItem> buckets;
    for (int i = 0; i < 8; ++i)
        buckets.push_back(bucket("b" + std::to_string(i), W0 + i * 20, W0 + i * 20 + 20, 50));
    const auto html = render_timeline_lanes(
        with_lane(lane("L-dns", "dns", "DNS cache", buckets, {rolled(TarTier::hourly)})));
    check_golden("lanes__dense-collapse-counts", html);
    contains(html, "8 buckets, 400 events");
    lacks(html, "8 events");
}

TEST_CASE("tar timeline golden: lanes unstated", "[tar][timeline][golden]") {
    auto m = base();
    m.groups[0].lanes[0].regions = {};
    m.groups[0].lanes[1].regions = {region(TarRegionKind::exact, W0, W0 + 1200)};
    const auto html = render_timeline_lanes(m);
    check_golden("lanes__unstated", html);
    contains(html, "Coverage not stated");
    CHECK(count_of(html, "tl-rg unstated") == 2);
}

// ═══ goldens: kept chart ══════════════════════════════════════════════════════════════

TEST_CASE("tar timeline golden: kept online", "[tar][timeline][golden]") {
    const auto m = kept_model(15 * kDay);
    const auto html = render_timeline_kept(m);
    check_golden("kept__online", html);

    // process: row-limited exact tier; bands exact -> hourly -> daily, no overlap
    const auto proc = kept_row_html(html, "process");
    contains(proc, "100000 rows kept; exact records reach back to " + std::string("2026-10-18T10:00:00Z") + " on this device");
    contains(proc, "tl-ks l\" style=\"left:0.000%;width:" + pct3(ax(2 * kDay)));
    contains(proc, "tl-ks h1\" style=\"left:" + pct3(ax(2 * kDay)) + "%;width:" + pct3(ax(20 * kDay) - ax(2 * kDay)));
    contains(proc, "tl-ks h2\" style=\"left:" + pct3(ax(20 * kDay)));
    contains(proc, "Hourly roll-up"); // the moment is 15 days back: the hourly tier
    contains(proc, "pruned 20 days after each hour starts, at the earliest");

    // arp: time-limited, daily tier at 15 days
    const auto arp = kept_row_html(html, "arp");
    contains(arp, "kept 1 day by default");
    contains(arp, "pruned 31 days after each day starts, at the earliest");

    // a tier with oldest_ts == 0 draws nothing: the service row has no hourly segment
    lacks(kept_row_html(html, "service"), "tl-ks h1");
    for (const char* s : {"tl-kp", "now", "1 hour", "1 year", "Age of the record"})
        contains(html, s);
}

TEST_CASE("tar timeline golden: kept paused long", "[tar][timeline][golden]") {
    const auto m = kept_model(15 * kDay);
    const auto html = render_timeline_kept(m);
    check_golden("kept__paused-long", html);
    // service paused 20 days before read_ts; exact oldest 25 days before read_ts
    const auto svc = kept_row_html(html, "service");
    contains(svc, "tl-ks none\" style=\"left:0.000%;width:" + pct3(ax(20 * kDay)));
    contains(svc, "tl-ks l\" style=\"left:" + pct3(ax(20 * kDay)) + "%;width:" + pct3(ax(25 * kDay) - ax(20 * kDay)));
    CHECK(count_of(svc, "tl-ks l\"") == 1); // the pause is counted once
    // the moment (15 days back) is newer than the pause
    contains(svc, "<span>Not recorded</span>");
    contains(svc, "Source paused since 2026-09-30T10:00:00Z");
}

TEST_CASE("tar timeline golden: kept offline", "[tar][timeline][golden]") {
    auto m = kept_model(15 * kDay);
    m.online = false;
    const auto html = render_timeline_kept(m);
    check_golden("kept__offline", html);
    contains(kept_row_html(html, "process"), "Not readable: device offline");
    contains(kept_row_html(html, "arp"), "Not readable: device offline");
    lacks(html, "res gone"); // not readable is not Gone: neither the word nor the faint style
}

TEST_CASE("tar timeline kept: the moment column states retention, never a rate or a remaining span",
          "[tar][timeline]") {
    // newest data: the row-limited exact tier
    const auto exact = render_timeline_kept(kept_model(3600));
    contains(kept_row_html(exact, "process"), "Exact records");
    contains(kept_row_html(exact, "process"), "kept until newer rows push it out");
    // older than every band: Gone
    const auto gone = render_timeline_kept(kept_model(59 * kDay));
    contains(kept_row_html(gone, "arp"), "Gone: nothing is kept this far back");
    contains(kept_row_html(gone, "arp"), "tl-kr");
    contains(gone, "res gone");
    // the note names the defaults and the tick / clock-guard caveat
    contains(exact, "The limits are the agent's defaults.");
    contains(exact, "Coverage is measured on this device");
    contains(exact, "prunes on its own tick and can decline a prune when its clock looks wrong");
    contains(exact, "records may outlive these limits");
    contains(exact, "counts or averages, not the events");
    // no "for <span> more" and no rate figure
    for (const auto* html : {&exact, &gone}) {
        CHECK_FALSE(std::regex_search(*html, std::regex("for [0-9]+ [a-z]+ more")));
        lacks(*html, "per day");
        lacks(*html, "rows a day");
    }
}

TEST_CASE("tar timeline kept: a source the engine could not measure says why, never Gone",
          "[tar][timeline]") {
    auto m = kept_model(15 * kDay);
    // Both rows have no measured band, and the lanes of base() read fine (exact regions), so
    // the chart cannot lean on a lane: the row itself carries the reason.
    auto failed = kept("process", "Processes", 100000, {band(TarTier::exact, 0), band(TarTier::hourly, 0)});
    failed.unreadable = TarUnreadableReason::read_failed;
    auto too_old = kept("arp", "ARP neighbours", 0, {});
    too_old.unreadable = TarUnreadableReason::agent_too_old;
    // control: a measured row with nothing observed this far back is still pruned, i.e. Gone
    m.kept = {failed, too_old, kept("service", "Services", 20000, {band(TarTier::exact, W1 - kDay)})};
    const auto html = render_timeline_kept(m);
    const auto proc = kept_row_html(html, "process");
    contains(proc, "<span>Not readable: the read failed</span>");
    lacks(proc, "Gone");
    lacks(proc, "res gone");
    const auto arp = kept_row_html(html, "arp");
    contains(arp, "<span>Not readable: the agent is too old for this read</span>");
    lacks(arp, "Gone");
    contains(kept_row_html(html, "service"), "Gone: nothing is kept this far back");
    contains(kept_row_html(html, "service"), "res gone"); // only a true Gone row takes the style

    // the moment panel says the same for a lane carrying the same reason
    m.groups = {TarTimelineGroup{
        "G",
        {lane("L-p", "process", "Processes", {},
              {unreadable(TarUnreadableReason::read_failed, m.window_from_ts, W1)}),
         lane("L-a", "arp", "ARP neighbours", {},
              {unreadable(TarUnreadableReason::agent_too_old, m.window_from_ts, W1)})}}};
    const auto moment = render_timeline_moment(m, tar_timeline_resolve_moment(m), links_full());
    contains(moment, "Processes: Not readable: the read failed");
    contains(moment, "ARP neighbours: Not readable: the agent is too old for this read");
    lacks(moment, "Gone");

    // a pause and an offline device are said first, as before
    m.kept[0].paused_since_ts = W1 - 20 * kDay;
    contains(kept_row_html(render_timeline_kept(m), "process"), "<span>Not recorded</span>");
    m.online = false;
    contains(kept_row_html(render_timeline_kept(m), "arp"), "<span>Not readable: device offline</span>");
}

TEST_CASE("tar timeline retention contract: measured coverage never changes an expiry statement",
          "[tar][timeline]") {
    std::string line, qualifier;
    for (std::int64_t oldest_days : {40, 55, 59}) {
        auto m = kept_model(15 * kDay);
        m.kept = {kept("arp", "ARP neighbours", 0,
                       {band(TarTier::exact, W1 - kDay, kDay), band(TarTier::hourly, W1 - 10 * kDay, 10 * kDay),
                        band(TarTier::daily, W1 - oldest_days * kDay, 31 * kDay)})};
        auto bk = bucket("BK", W0 + 100, W0 + 160, 3, TarTier::daily);
        m.groups = {TarTimelineGroup{"G", {lane("L-arp", "arp", "ARP neighbours", {bk})}}};
        const auto sel = render_timeline_selected(m, "BK", W0 + 120, links_full());
        const auto kept_html = render_timeline_kept(m);
        const auto a = sel.find("Pruned after");
        REQUIRE(a != std::string::npos);
        const auto l = sel.substr(a, sel.find("</b>", a) - a);
        const auto q0 = kept_html.find("pruned 31 days");
        REQUIRE(q0 != std::string::npos);
        const auto q = kept_html.substr(q0, kept_html.find("<", q0) - q0);
        if (line.empty()) {
            line = l;
            qualifier = q;
        }
        CHECK(l == line);
        CHECK(q == qualifier);
    }
}

// ═══ goldens: device bar ══════════════════════════════════════════════════════════════

TEST_CASE("tar timeline golden: device bar online", "[tar][timeline][golden]") {
    const auto html = render_timeline_device_bar(base(), links_full());
    check_golden("device-bar__online", html);
    contains(html, "host-a");
    contains(html, "Online");
    contains(html, "Choose another device");
    contains(html, "Open device");
    contains(html, "Processes <span class=\"pill ok\">On</span>");
    // links render only when injected
    const auto bare = render_timeline_device_bar(base(), TarTimelineLinks{});
    lacks(bare, "Choose another device");
    lacks(bare, "Open device");
}

TEST_CASE("tar timeline golden: device bar offline and paused", "[tar][timeline][golden]") {
    auto m = base();
    m.online = false;
    m.hostname.clear(); // falls back to agent_id, never blank
    m.sources[4].paused_since_ts = W0 - 3 * kDay;
    m.sources[2].enabled = false;
    const auto html = render_timeline_device_bar(m, TarTimelineLinks{});
    check_golden("device-bar__offline-paused", html);
    contains(html, "agent-1");
    contains(html, "Offline");
    contains(html, "Services <span class=\"pill warn\">Paused since 2026-10-17T09:00:00Z</span>");
    contains(html, "DNS cache <span class=\"pill idle\">Off</span>");
    m.agent_id.clear();
    contains(render_timeline_device_bar(m, TarTimelineLinks{}), "Unknown device");
}

// ═══ goldens: limits ══════════════════════════════════════════════════════════════════

namespace {
void limits_always(const std::string& html) {
    contains(html, "What this record cannot tell you");
    contains(html, "no starting snapshot");
    contains(html, "TAR does not record file changes");
    contains(html, escaped("The limits shown are the agent's defaults"));
    lacks(html, "event-driven");
}
} // namespace

TEST_CASE("tar timeline golden: limits windows etw", "[tar][timeline][golden]") {
    auto m = base();
    const auto html = render_timeline_limits(m, links_full());
    check_golden("limits__windows-etw", html);
    limits_always(html);
    contains(html, "every 60 seconds");
    contains(html, "Windows ETW event stream");
    contains(html, "carries snapshot times");
    contains(html, "Command lines are not recorded on Windows; process names only.");
    contains(html, "The DNS cache does not say which process asked.");
}

TEST_CASE("tar timeline golden: limits windows polling fallback", "[tar][timeline][golden]") {
    auto m = base();
    m.process_capture_method = "polling";
    const auto html = render_timeline_limits(m, links_full());
    check_golden("limits__windows-polling-fallback", html);
    limits_always(html);
    contains(html, "a process that starts and exits between reads is missed");
    lacks(html, "event stream");
    contains(html, escaped("Command lines are not recorded on Windows; the executable's path is "
                           "recorded, not its arguments."));
    lacks(html, "process names only");
}

TEST_CASE("tar timeline golden: limits macos polling", "[tar][timeline][golden]") {
    auto m = base();
    m.os = "macOS 15";
    m.process_capture_method = "polling";
    const auto html = render_timeline_limits(m, links_full());
    check_golden("limits__macos-polling", html);
    limits_always(html);
    contains(html, escaped("Command lines are not recorded on macOS; the executable's path is "
                           "recorded, not its arguments."));
    lacks(html, "process names only");
    lacks(html, "event stream");
    m.process_capture_method = "endpoint_security";
    const auto es = render_timeline_limits(m, links_full());
    contains(es, "Endpoint Security event stream");
    contains(es, "Command lines are not recorded on macOS; process names only.");
}

TEST_CASE("tar timeline golden: limits linux unknown poll", "[tar][timeline][golden]") {
    auto m = base();
    m.os = "Ubuntu 26.04";
    m.process_capture_method.clear();
    m.poll_interval_s.reset();
    m.groups[1].lanes.erase(m.groups[1].lanes.begin() + 1); // no dns lane ...
    m.sources.erase(m.sources.begin() + 2);                  // ... and no dns source
    const auto html = render_timeline_limits(m, links_full());
    check_golden("limits__linux-unknown-poll", html);
    limits_always(html);
    contains(html, escaped("read on the agent's polling interval, not continuously"));
    lacks(html, "seconds, not continuously"); // no guessed number
    lacks(html, "Command lines are not recorded");
    lacks(html, "DNS cache does not say");
    lacks(html, "event stream");
}

TEST_CASE("tar timeline golden: limits offline", "[tar][timeline][golden]") {
    auto m = base();
    m.online = false;
    m.sources[4].paused_since_ts = W0 - 3 * kDay;
    m.groups[0].lanes[0].regions = {capped(W0, W0 + 1800, 10000, W0 + 1800)};
    const auto html = render_timeline_limits(m, links_full());
    check_golden("limits__offline", html);
    limits_always(html);
    contains(html, "Not readable");
    contains(html, "Services is paused since 2026-10-17T09:00:00Z");
    contains(html, "href=\"/tar#paused\"");
    contains(html, "The read of proc-a.exe was cut off at 10000 rows");
}

TEST_CASE("tar timeline limits: the capture claim comes from the method, never from the OS",
          "[tar][timeline]") {
    const std::string unknown = "The agent did not state how processes are captured. If it polls, a "
                                "process that starts and exits between reads is missed and start "
                                "times are snapshot times.";
    auto m = base();
    m.os = "Windows 11";
    m.process_capture_method.clear(); // unknown: said so, no stream and no polling claimed
    const auto empty = render_timeline_limits(m, links_full());
    lacks(empty, "event stream");
    lacks(empty, escaped("Processes are read on the agent's polling interval"));
    contains(empty, unknown);
    // an unknown method says no more about command lines than that they are not recorded
    contains(empty, "Command lines are not recorded on Windows.");
    lacks(empty, "process names only");
    lacks(empty, "path is recorded");
    m.process_capture_method = "something-new"; // unrecognised: the same, and the value never shows
    const auto html = render_timeline_limits(m, links_full());
    lacks(html, "event stream");
    lacks(html, "something-new");
    lacks(html, escaped("Processes are read on the agent's polling interval"));
    contains(html, unknown);
    // only the agent saying "polling" asserts polling
    m.process_capture_method = "polling";
    const auto polled = render_timeline_limits(m, links_full());
    contains(polled, escaped("Processes are read on the agent's polling interval"));
    lacks(polled, "did not state");
}

// ═══ goldens: moment ══════════════════════════════════════════════════════════════════

TEST_CASE("tar timeline golden: moment exact", "[tar][timeline][golden]") {
    std::vector<TarTimelineItem> alive;
    for (int i = 1; i <= 14; ++i)
        alive.push_back(bar("X" + std::to_string(i), W0 + 600, W0 + 2400, "proc-" + std::to_string(i) + ".exe"));
    auto m = with_lane(lane("L-p", "process", "Processes", alive), "Processes");
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    check_golden("moment__exact", html);
    CHECK(count_of(html, "class=\"tl-pr") == 12);
    contains(html, "and 2 more");
    contains(html, "2026-10-20T09:30:00Z");
    // previous / next render as links only when the builder is set
    contains(html, "<a class=\"btn sm\" href=\"/tar/moment?t=" + std::to_string(W0 + 600) +
                        "\" data-ts=\"" + std::to_string(W0 + 600) + "\">Previous event</a>");
    contains(html, "Next event</a>");
    const auto bare = render_timeline_moment(m, W0 + 1800, TarTimelineLinks{});
    contains(bare, "<button type=\"button\" class=\"btn sm\" disabled>Previous event</button>");
    contains(bare, "disabled>Next event</button>");
    // an exact lane with nothing at t says so, it is not silent
    const auto none = render_timeline_moment(with_lane(lane("L", "dns", "DNS cache", {}), "Network"), W0 + 5, links_full());
    contains(none, "DNS cache: Nothing at this time");
}

TEST_CASE("tar timeline golden: moment rolled up", "[tar][timeline][golden]") {
    auto m = with_lane(lane("L-dns", "dns", "DNS cache", {bucket("B1", W0, W1, 14)}, {rolled(TarTier::hourly)}), "Network");
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    check_golden("moment__rolled-up", html);
    contains(html, "DNS cache: Hourly roll-up: counts only; exact times are not kept.");
    contains(html, "14 events");
}

TEST_CASE("tar timeline golden: moment rolled up perf", "[tar][timeline][golden]") {
    auto m = with_lane(lane("L-perf", "perf", "CPU", {column("K1", W0, W1, 61, TarTier::hourly)}, {rolled(TarTier::hourly)}), "System");
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    check_golden("moment__rolled-up-perf", html);
    contains(html, "averages and peaks for the whole hour");
    contains(html, "the individual samples are not kept");
    lacks(html, "counts only");
}

TEST_CASE("tar timeline golden: moment mixed lanes", "[tar][timeline][golden]") {
    auto m = base();
    m.groups = {TarTimelineGroup{
        "Mixed",
        {lane("L-p", "process", "Processes", {bar("X1", W0 + 600, W0 + 2400, "proc-a.exe")}),
         lane("L-t", "tcp", "TCP connections", {}, {capped(W0, W1, 10000, W0 + 1000)}),
         lane("L-s", "service", "Service changes", {}, {unreadable(TarUnreadableReason::read_failed)}),
         lane("L-d", "dns", "DNS cache", {bucket("B1", W0, W1, 4)}, {rolled(TarTier::hourly)}),
         lane("L-a", "arp", "ARP neighbours", {bucket("B2", W0, W1, 9)}, {rolled(TarTier::hourly)})}}};
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    check_golden("moment__mixed-lanes", html);
    // distinct state lines, each naming its lane
    contains(html, "TCP connections: The read was cut off at 10000 rows; nothing before 2026-10-20T09:16:40Z is shown");
    contains(html, "Service changes: Not readable: the read failed");
    // identical rolled-up states merge into one line naming both
    contains(html, "DNS cache, ARP neighbours: Hourly roll-up: counts only; exact times are not kept.");
    CHECK(count_of(html, "Hourly roll-up") == 1);
    // the exact lane lists its item with the lane named
    contains(html, "<span class=\"nm\">proc-a.exe</span><span class=\"pid\">Processes</span>");
}

TEST_CASE("tar timeline golden: moment pruned", "[tar][timeline][golden]") {
    auto m = with_lane(lane("L-d", "dns", "DNS cache", {}, {region(TarRegionKind::pruned)}), "Network");
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    check_golden("moment__pruned", html);
    contains(html, "DNS cache: Nothing is kept for this time");
}

TEST_CASE("tar timeline golden: moment paused", "[tar][timeline][golden]") {
    auto m = with_lane(lane("L-s", "service", "Service changes", {}, {paused(W0, W1, W0 - kDay)}), "System");
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    check_golden("moment__paused", html);
    contains(html, "Service changes: Not recorded since 2026-10-19T09:00:00Z");
}

TEST_CASE("tar timeline golden: moment offline", "[tar][timeline][golden]") {
    auto m = base();
    m.online = false;
    for (auto& g : m.groups)
        for (auto& l : g.lanes)
            l.regions = {unreadable(TarUnreadableReason::offline)};
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    check_golden("moment__offline", html);
    contains(html, "Not readable: device offline");
    lacks(html, "class=\"tl-pr");
}

TEST_CASE("tar timeline golden: moment capped", "[tar][timeline][golden]") {
    auto m = with_lane(lane("L-p", "process", "Processes", {}, {capped(W0, W1, 10000, W0 + 3000)}), "Processes");
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    check_golden("moment__capped", html);
    contains(html, "Processes: The read was cut off at 10000 rows; nothing before 2026-10-20T09:50:00Z is shown");
}

TEST_CASE("tar timeline moment: a rolled-up process lane says what it no longer holds",
          "[tar][timeline]") {
    auto m = with_lane(lane("L-p", "process", "Processes", {bucket("PB", W0, W1, 31)}, {rolled(TarTier::hourly)}),
                       "Processes");
    m.groups[0].lanes.push_back(lane("L-d", "dns", "DNS cache", {bucket("DB", W0, W1, 4)}, {rolled(TarTier::hourly)}));
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    contains(html, "Processes: Hourly roll-up: counts only; parents, process ids and exact times are not kept.");
    // the same tier for another source is its own line with the plain sentence
    contains(html, "DNS cache: Hourly roll-up: counts only; exact times are not kept.");
    CHECK(count_of(html, "Hourly roll-up") == 2);
    lacks(html, "averages and peaks");
}

TEST_CASE("tar timeline monthly tier: every surface names it", "[tar][timeline]") {
    auto m = with_lane(lane("L-dns", "dns", "DNS cache", {bucket("MB", W0, W1, 120, TarTier::monthly)},
                            {rolled(TarTier::monthly)}),
                       "Network");
    m.window_from_ts = W1 - 200 * kDay;
    m.moment_ts = W1 - 100 * kDay; // only the monthly tier reaches this far back
    m.kept = {kept("dns", "DNS cache", 0,
                   {band(TarTier::exact, W1 - kDay, kDay), band(TarTier::hourly, W1 - 10 * kDay, 10 * kDay),
                    band(TarTier::daily, W1 - 60 * kDay, 60 * kDay),
                    band(TarTier::monthly, W1 - 400 * kDay, 400 * kDay)})};
    // lanes: the region reason
    const auto lanes = render_timeline_lanes(m);
    contains(lanes, "tl-rg rolled");
    contains(lanes, "<b>Monthly roll-up</b>");
    // moment: the roll-up sentence, and the perf wording names the month
    contains(render_timeline_moment(m, W0 + 1800, links_full()),
             "DNS cache: Monthly roll-up: counts only; exact times are not kept.");
    const auto perf = with_lane(
        lane("L-perf", "perf", "CPU", {column("K1", W0, W1, 55, TarTier::monthly)}, {rolled(TarTier::monthly)}),
        "System");
    contains(render_timeline_moment(perf, W0 + 1800, links_full()),
             "CPU: Monthly roll-up: averages and peaks for the whole month; the individual samples are not kept.");
    // selected: the pill and the expiry basis (from_ts + policy_s)
    const auto sel = render_timeline_selected(m, "MB", W0 + 100, links_full());
    contains(sel, "<span class=\"pill warn\">Monthly roll-up</span>");
    contains(sel, "Pruned after 2027-11-24T09:00:00Z at the earliest (a bucket ages from its start");
    // kept: the h3 segment runs from the daily tier's reach to the monthly oldest; the column
    // at the moment names the tier and its configured policy
    const auto kept_html = render_timeline_kept(m);
    const auto row = kept_row_html(kept_html, "dns");
    contains(row, "tl-ks h3\" style=\"left:" + pct3(ax(60 * kDay)) + "%;width:" +
                      pct3(ax(400 * kDay) - ax(60 * kDay)));
    contains(row, "<span>Monthly roll-up</span>");
    contains(row, "pruned 400 days after each month starts, at the earliest");
}

// ═══ goldens: selected ════════════════════════════════════════════════════════════════

TEST_CASE("tar timeline golden: selected bar row limited", "[tar][timeline][golden]") {
    const auto html = render_timeline_selected(base(), "P2", W0 + 3300, links_full());
    check_golden("selected__bar-row-limited", html);
    contains(html, "Kept until newer rows push it past the 100000-row limit; no date can be given");
    contains(html, "Flagged");
    contains(html, "<span class=\"pill ok\">Exact</span>");
    // the linked id that exists becomes a button; the unknown one is dropped
    contains(html, "href=\"/tar/selected?ref=P1&amp;t=" + std::to_string(W0 + 3300) + "\"");
    lacks(html, "gone-id");
    // no date in the retention line
    const auto a = html.find("Kept until newer rows");
    REQUIRE(a != std::string::npos);
    const auto line = html.substr(a, html.find("</b>", a) - a);
    CHECK_FALSE(std::regex_search(line, std::regex("[0-9]{4}-[0-9]{2}-[0-9]{2}")));
    // facts render as key/value rows
    const auto p1 = render_timeline_selected(base(), "P1", W0 + 1000, links_full());
    contains(p1, "<div><span>Started by</span><b>proc-b.exe 100</b></div>");
}

TEST_CASE("tar timeline golden: selected count time limited", "[tar][timeline][golden]") {
    auto bk = bucket("BK", W0, W0 + 3600, 12, TarTier::daily);
    bk.title = "ARP, 12 neighbours";
    auto m = with_lane(lane("L-arp", "arp", "ARP neighbours", {bk}, {rolled(TarTier::daily)}), "Network");
    const auto html = render_timeline_selected(m, "BK", W0 + 100, links_full());
    check_golden("selected__count-time-limited", html);
    // from_ts + policy_s (31 days): a bucket ages from its start
    contains(html, "Pruned after 2026-11-20T09:00:00Z at the earliest (a bucket ages from its start; the agent prunes on its own tick and may hold it longer)");
    contains(html, "<span class=\"pill warn\">Daily roll-up</span>");
}

TEST_CASE("tar timeline golden: selected not found", "[tar][timeline][golden]") {
    const auto html = render_timeline_selected(base(), "nope", W0, links_full());
    check_golden("selected__not-found", html);
    contains(html, "That item is not in this read. Click a process, a count, a connection or a marker.");
    CHECK_FALSE(html.empty());
}

TEST_CASE("tar timeline selected: retention is stated only from policy, else not stated",
          "[tar][timeline]") {
    // policy_s == 0 and row_limit == 0: not stated
    auto m = with_lane(lane("L", "dns", "DNS cache", {bar("D", W0, W0 + 100)}), "Network");
    m.kept = {kept("dns", "DNS cache", 0, {band(TarTier::exact, W0 - kDay, 0)})};
    contains(render_timeline_selected(m, "D", W0, links_full()), "How long this is kept is not stated");
    // no kept row at all: also not stated
    m.kept.clear();
    contains(render_timeline_selected(m, "D", W0, links_full()), "How long this is kept is not stated");
    // time-limited exact tier
    m.kept = {kept("dns", "DNS cache", 0, {band(TarTier::exact, W0 - kDay, 20 * 3600)})};
    contains(render_timeline_selected(m, "D", W0, links_full()),
             "Pruned after 2026-10-21T05:00:00Z at the earliest (a record ages from its start");
    // the unlinked panel never shows linked buttons without a builder
    auto p = render_timeline_selected(base(), "P2", W0, TarTimelineLinks{});
    lacks(p, "tl-lk");
}

// ═══ escaping and honesty ═════════════════════════════════════════════════════════════

namespace {
std::string hostile(const std::string& slot) { return "<script>alert('" + slot + "')</script>\" onmouseover=\"x"; }
} // namespace

TEST_CASE("tar timeline escaping: hostile strings in every dynamic slot", "[tar][timeline]") {
    auto m = base();
    m.hostname = hostile("hostname");
    m.os = hostile("os");
    m.process_capture_method = hostile("capture");
    m.sources[0].label = hostile("source-label");
    m.kept[0].label = hostile("kept-label");
    auto a = bar(hostile("item-id"), W0 + 100, W0 + 900, hostile("item-label"));
    a.title = hostile("item-title");
    a.facts = {{hostile("fact-key"), hostile("fact-value")}};
    auto b = bar(hostile("item-id-2"), W0 + 1000, W0 + 1500, hostile("item-label-2"));
    a.linked_ids = {b.id};
    auto l = lane(hostile("lane-id"), hostile("lane-source"), hostile("lane-name"), {a, b});
    l.sub = hostile("lane-sub");
    m.groups = {TarTimelineGroup{hostile("group-name"), {l}}};
    m.kept.push_back(kept(hostile("lane-source"), hostile("kept-label-2"), 5, {band(TarTier::exact, W0 - kDay)}));
    TarTimelineLinks links = links_full();
    links.device = hostile("link-device");
    links.choose_device = hostile("link-choose");
    links.retention_paused = hostile("link-paused");
    links.moment = [](std::int64_t) { return hostile("link-moment"); };
    links.selected = [](const std::string&, std::int64_t) { return hostile("link-selected"); };
    m.sources[4].paused_since_ts = W0 - kDay;
    m.sources[4].label = hostile("paused-label");

    std::string all;
    for (const auto& s : all_outputs(m, links, a.id))
        all += s;
    lacks(all, "<script>");
    lacks(all, "\" onmouseover=\"x");
    lacks(all, "alert('");
    for (const char* slot : {"hostname", "os", "source-label", "kept-label", "item-id", "item-label", "item-title",
                             "fact-key", "fact-value", "item-id-2", "item-label-2", "lane-id", "lane-source",
                             "lane-name", "lane-sub", "group-name", "link-device", "link-choose", "link-paused",
                             "link-moment", "link-selected", "paused-label"})
        contains(all, escaped(hostile(slot)));
    // an unrecognised capture method renders the not-stated sentence and never the value itself
    lacks(all, escaped(hostile("capture")));
    contains(all, "The agent did not state how processes are captured.");

    // agent_id is shown when the hostname is empty
    m.hostname.clear();
    m.agent_id = hostile("agent-id");
    contains(render_timeline_device_bar(m, TarTimelineLinks{}), escaped(hostile("agent-id")));
    // a hostile selected ref that is not in the read never echoes
    lacks(render_timeline_selected(m, hostile("ref"), W0, links), "alert(");

    // the ampersand case: an already-escaped looking string is escaped again, not trusted
    auto amp = with_lane(lane("L", "process", "&amp;", {bar("p", W0, W0 + 60, "&amp;")}));
    contains(render_timeline_lanes(amp), "&amp;amp;");
}

TEST_CASE("tar timeline honesty: no fleet claim, no guessed figure, no invented urgency",
          "[tar][timeline]") {
    std::vector<TarTimelineModel> models;
    models.push_back(base());
    auto off = base();
    off.online = false;
    models.push_back(off);
    models.push_back(kept_model(15 * kDay));
    models.push_back(kept_model(59 * kDay));
    // the states the goldens draw: paused (stated and not reported), capped, pruned, rolled up
    auto paused_m = base();
    paused_m.groups[2].lanes[0].regions = {region(TarRegionKind::exact, W0, W0 + 1800),
                                           paused(W0 + 1800, W1, W0 + 1800)};
    paused_m.sources[4].paused_since_ts = W0 - 3 * kDay;
    paused_m.sources[3].paused = true;
    paused_m.kept[2].paused_since_ts = 0;
    paused_m.kept[2].paused = true;
    models.push_back(paused_m);
    auto capped_m = base();
    capped_m.groups[0].lanes[0].regions = {capped(W0, W0 + 1800, 10000, W0 + 1800),
                                           region(TarRegionKind::exact, W0 + 1800, W1)};
    models.push_back(capped_m);
    auto pruned_m = base();
    pruned_m.groups[1].lanes[1].regions = {region(TarRegionKind::pruned, W0, W0 + 1800),
                                           region(TarRegionKind::exact, W0 + 1800, W1)};
    models.push_back(pruned_m);
    models.push_back(with_lane(lane("L-dns", "dns", "DNS cache", {bucket("B1", W0, W1, 14)},
                                    {rolled(TarTier::hourly)})));
    for (const auto& m : models) {
        for (const auto& out : all_outputs(m, links_full())) {
            lacks(out, "devices that answered");
            lacks(out, "Across the fleet");
            lacks(out, "Go to the incident");
            lacks(out, "event-driven");
            CHECK_FALSE(std::regex_search(out, std::regex("about [0-9]")));
            CHECK_FALSE(std::regex_search(out, std::regex("for [0-9]+ [a-z]+ more")));
            // every rendered time carries the Z
            CHECK_FALSE(std::regex_search(out, std::regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}(?!Z)")));
        }
        CHECK(count_of(render_timeline_lanes(m), "UTC") == 1);
    }
}

// ═══ extreme and hostile inputs ═══════════════════════════════════════════════════════

namespace {
constexpr std::int64_t kMin = std::numeric_limits<std::int64_t>::min();
constexpr std::int64_t kMax = std::numeric_limits<std::int64_t>::max();
constexpr std::int64_t kYear9999 = 253402300799; // 9999-12-31T23:59:59Z, the last time stated
bool in_percent_range(double v) { return std::isfinite(v) && v >= 0.0 && v <= 100.0; }

TarRegionKind kind_in(const TarTimelineLane& l, std::int64_t t) {
    const auto* r = tar_timeline_region_at(l, t);
    REQUIRE(r != nullptr);
    return r->kind;
}
} // namespace

TEST_CASE("tar timeline extreme timestamps: positions stay finite and in range", "[tar][timeline]") {
    auto m = base();
    // an item that began before the representable past and ends inside the window
    const auto early =
        tar_timeline_layout_lane(lane("l", "process", "p", {bar("early", kMin, W0 + 600)}), m);
    REQUIRE(early.blocks.size() == 1);
    CHECK(early.blocks[0].left_pct == 0.0);
    CHECK(in_percent_range(early.blocks[0].width_pct));
    CHECK(pct3(early.blocks[0].width_pct) == pct3(tar_timeline_pct(m, W0 + 600)));
    CHECK(early.blocks[0].cls.find(" cl") != std::string::npos);
    // ... and one that starts at the far end of time is outside the window
    CHECK(tar_timeline_layout_lane(lane("l", "process", "p", {bar("late", kMax, 0), tick("t", kMax)}), m)
              .blocks.empty());

    // a window as wide as int64: every position is finite and in range
    auto wide = base();
    wide.window_from_ts = kMin;
    wide.window_to_ts = kMax;
    wide.moment_ts = 0;
    for (const std::int64_t ts : {kMin, W0, kMax})
        CHECK(in_percent_range(tar_timeline_pct(wide, ts)));
    CHECK(tar_timeline_pct(wide, kMin) == 0.0);
    CHECK(tar_timeline_pct(wide, kMax) == 100.0);
    CHECK(std::abs(tar_timeline_pct(wide, 0) - 50.0) < 0.001);
    for (const auto& out : all_outputs(wide, links_full()))
        CHECK_FALSE(out.empty());

    // a window at the very top: its two ends are one double, so it is degenerate, not undefined
    auto top = base();
    top.window_from_ts = kMax - 1000;
    top.window_to_ts = kMax;
    for (const std::int64_t ts : {kMin, W0, kMax - 500, kMax})
        CHECK(in_percent_range(tar_timeline_pct(top, ts)));
    for (const auto& out : all_outputs(top, links_full()))
        CHECK_FALSE(out.empty());

    // an inverted window draws nothing and does not compute with itself
    auto inv = base();
    inv.window_to_ts = inv.window_from_ts - 3600;
    CHECK(tar_timeline_pct(inv, W0 + 10) == 0.0);
    CHECK(tar_timeline_layout_lane(lane("l", "process", "p", {bar("a", W0, W0 + 10)}), inv).blocks.empty());
    for (const auto& out : all_outputs(inv, links_full()))
        CHECK_FALSE(out.empty());
}

TEST_CASE("tar timeline collapse: a count sum saturates and says so, never wraps", "[tar][timeline]") {
    auto m = base();
    // Eight tiny buckets: `first` in the first, `rest` in each of the other seven.
    auto collapsed = [&](std::int64_t first, std::int64_t rest) {
        std::vector<TarTimelineItem> v;
        for (int i = 0; i < 8; ++i)
            v.push_back(bucket("b" + std::to_string(i), W0 + i * 20, W0 + i * 20 + 20,
                               i == 0 ? first : rest));
        const auto lay = tar_timeline_layout_lane(lane("l", "dns", "d", v), m);
        REQUIRE(lay.blocks.size() == 1);
        REQUIRE(lay.blocks[0].collapsed);
        return lay.blocks[0];
    };
    // 8 x 2^60 is one past the largest int64: capped, and the label says it is a lower bound
    const auto huge = collapsed(std::int64_t{1} << 60, std::int64_t{1} << 60);
    CHECK(huge.label == "8 buckets, at least 9223372036854775807 events");
    CHECK(huge.title == huge.label);
    // a total that lands exactly on the maximum is exact, not "at least"
    CHECK(collapsed((std::int64_t{1} << 60) - 1, std::int64_t{1} << 60).label ==
          "8 buckets, 9223372036854775807 events");
    // a negative count is not a count: it adds nothing and never cancels another bucket
    CHECK(collapsed(-5, 50).label == "8 buckets, 350 events");
    CHECK(collapsed(kMin, 50).label == "8 buckets, 350 events");
    CHECK(collapsed(kMax, kMax).label == "8 buckets, at least 9223372036854775807 events");
}

TEST_CASE("tar timeline window: one outside 1970..9999 says so and draws nothing", "[tar][timeline]") {
    struct Win {
        std::int64_t from, to;
    };
    // the top of int64 (both ends are one double), past year 9999, before 1970, the epoch, and a
    // window that ends before it starts
    for (const Win w : {Win{kMax - 1000, kMax}, Win{W0, kYear9999 + 1}, Win{kMin, W1}, Win{0, W1},
                        Win{W1, W0}}) {
        INFO("window " << w.from << " .. " << w.to);
        const std::vector<TarTimelineItem> items{bar("a", w.from + 1, w.from + 2), tick("t", w.from + 1)};
        auto m = with_lane(lane("l", "process", "p", items, {}), "G");
        m.window_from_ts = w.from;
        m.window_to_ts = w.to;
        m.moment_ts = 0;
        CHECK(tar_timeline_layout_lane(m.groups[0].lanes[0], m).blocks.empty());
        const auto html = render_timeline_lanes(m);
        const std::string warn =
            "<div class=\"tl-warn\">The time window is not valid: it ends before it starts, or lies "
            "outside the years 1970 to 9999, so nothing can be drawn.</div>";
        contains(html, warn);
        CHECK(html.find(warn) < html.find("<div class=\"tl\">"));
        // the banner is true: no item, no region stretch and no playhead or future shade is drawn
        CHECK(count_of(html, "<button type=\"button\" class=\"tl-") == 0);
        lacks(html, "tl-rg");
        lacks(html, "tl-ph");
        lacks(html, "tl-fut");
    }
    // a valid window, up to the last representable second, carries no banner
    auto edge = base();
    edge.window_from_ts = kYear9999 - 1000;
    edge.window_to_ts = kYear9999;
    for (const auto& m : {base(), edge}) {
        const auto html = render_timeline_lanes(m);
        lacks(html, "The time window is not valid");
        contains(html, "tl-ph"); // a valid window keeps its playhead and future shade
        contains(html, "tl-fut");
    }
}

TEST_CASE("tar timeline ruler: a window outside 1970..9999 draws no ruler and always ends",
          "[tar][timeline]") {
    struct Win {
        std::int64_t from, to;
    };
    for (const Win w : {Win{kMax - 1000, kMax}, Win{kMax - 600, kMax - 1}, Win{kMin, kMax},
                        Win{kMin, kMin + 1000}, Win{0, 600}, Win{W0, kYear9999 + 1}}) {
        INFO("window " << w.from << " .. " << w.to);
        auto m = base();
        m.window_from_ts = w.from;
        m.window_to_ts = w.to;
        m.moment_ts = 0;
        CHECK(ruler_labels(render_timeline_lanes(m)).empty());
    }
    // the last representable second is inside the guard: a short window there still draws
    auto edge = base();
    edge.window_from_ts = kYear9999 - 1000;
    edge.window_to_ts = kYear9999;
    edge.moment_ts = 0;
    const auto labels = ruler_labels(render_timeline_lanes(edge));
    CHECK_FALSE(labels.empty());
    CHECK(labels.size() <= 31);
}

TEST_CASE("tar timeline selected: retention never states a wrapped or out-of-range date",
          "[tar][timeline]") {
    auto model = [](std::int64_t from_ts) {
        auto m = with_lane(lane("L", "arp", "ARP neighbours", {bar("it", from_ts, 0)}), "G");
        m.kept = {kept("arp", "ARP neighbours", 0, {band(TarTier::exact, W0 - kDay, kDay)})};
        return m;
    };
    // before the representable past, no start at all, at the far end, and an expiry past year 9999
    for (const std::int64_t from : {kMin, std::int64_t{0}, kMax, kYear9999 - 10}) {
        INFO("item start " << from);
        const auto sel = render_timeline_selected(model(from), "it", W0, links_full());
        contains(sel, "Pruned 1 day after it starts, at the earliest");
        lacks(sel, "Pruned after");
        lacks(sel, "1900-");
    }
    // control: an ordinary start still gets the dated sentence
    contains(render_timeline_selected(model(W0), "it", W0, links_full()),
             "Pruned after 2026-10-21T09:00:00Z at the earliest (a record ages from its start");
}

TEST_CASE("tar timeline times: one past year 9999 is said in words, never as 1900-", "[tar][timeline]") {
    auto m = kept_model(15 * kDay);
    m.read_ts = kMax;
    // the exact band reaches back further than the pause, so both segments draw
    m.kept = {kept("process", "Processes", 100000, {band(TarTier::exact, kMax / 4)}, kMax / 2)};
    const auto html = render_timeline_kept(m);
    contains(html, "oldest observed a time outside the recordable range");
    contains(html, "exact records reach back to a time outside the recordable range on this device");
    lacks(html, "1900-");
    // the device bar chip and a limits bullet say the same; the playhead chip cannot, because a
    // window outside 1970..9999 draws no playhead at all
    auto top = base();
    top.window_from_ts = kMax - 1000;
    top.window_to_ts = kMax;
    top.moment_ts = kMax;
    top.sources[4].paused_since_ts = kMax;
    std::string all;
    for (const auto& s : all_outputs(top, links_full()))
        all += s;
    lacks(render_timeline_lanes(top), "tl-ph");
    contains(all, "Services <span class=\"pill warn\">Paused since a time outside the recordable range</span>");
    lacks(all, "1900-");
}

TEST_CASE("tar timeline moment: an offline device reads Not readable whatever the regions say",
          "[tar][timeline]") {
    auto m = base();
    m.online = false; // the engine left every lane's exact region in place
    const auto html = render_timeline_moment(m, W0 + 1800, links_full());
    CHECK(count_of(html, "Not readable: device offline") == 3); // one merged line per group
    lacks(html, "Nothing at this time");
    lacks(html, "class=\"tl-pr");
    // the same model online lists its items, so the guard is what changed the answer
    m.online = true;
    contains(render_timeline_moment(m, W0 + 1800, links_full()), "class=\"tl-pr");
}

TEST_CASE("tar timeline empty model: every renderer says something", "[tar][timeline]") {
    const TarTimelineModel empty; // no groups, offline, a zero-width window
    const auto outs = all_outputs(empty, links_full());
    for (const auto& out : outs)
        CHECK_FALSE(out.empty());
    contains(outs[0], "Unknown device");
    contains(outs[2], "No lanes in this read.");
    contains(outs[2], "The time window is not valid: it ends before it starts, or lies outside the "
                      "years 1970 to 9999, so nothing can be drawn.");
    contains(outs[4], "Nothing in this read.");
    contains(outs[5], "That item is not in this read.");

    // an online, valid window with no lanes says only the lane part
    auto none = base();
    none.groups.clear();
    const auto lanes = render_timeline_lanes(none);
    contains(lanes, "<div class=\"tl-empty\">No lanes in this read.</div>");
    lacks(lanes, "The time window is not valid");
    contains(render_timeline_moment(none, W0 + 1800, links_full()), "<div class=\"tl-empty\">Nothing in this read.</div>");

    // an inverted or zero-width window is said before the chart
    for (const std::int64_t to : {W0 - 60, W0}) {
        auto inv = base();
        inv.window_to_ts = to;
        const auto html = render_timeline_lanes(inv);
        const std::string warn = "<div class=\"tl-warn\">The time window is not valid";
        contains(html, warn);
        CHECK(html.find(warn) < html.find("<div class=\"tl\">"));
    }
    lacks(render_timeline_lanes(base()), "The time window is not valid");
}

TEST_CASE("tar timeline region_at: overlapping, unsorted and zero-length regions agree with the lane",
          "[tar][timeline]") {
    const auto exact_a = region(TarRegionKind::exact, W0, W0 + 100);
    const auto pruned_b = region(TarRegionKind::pruned, W0 + 50, W0 + 100);
    for (const bool pruned_first : {false, true}) {
        INFO("pruned region first in the vector: " << pruned_first);
        std::vector<TarTimelineRegion> rs{exact_a, pruned_b};
        if (pruned_first)
            std::swap(rs[0], rs[1]);
        const auto l = lane("l", "process", "p", {}, rs);
        CHECK(kind_in(l, W0 + 25) == TarRegionKind::exact);
        CHECK(kind_in(l, W0 + 75) == TarRegionKind::pruned);  // the later start is drawn on top
        CHECK(kind_in(l, W0 + 100) == TarRegionKind::pruned); // closed end: the same winner
    }
    // equal starts: the later region in vector order is drawn on top
    for (const bool pruned_last : {false, true}) {
        std::vector<TarTimelineRegion> rs{region(TarRegionKind::exact, W0, W0 + 100),
                                          region(TarRegionKind::pruned, W0, W0 + 100)};
        if (!pruned_last)
            std::swap(rs[0], rs[1]);
        CHECK(kind_in(lane("l", "process", "p", {}, rs), W0 + 10) ==
              (pruned_last ? TarRegionKind::pruned : TarRegionKind::exact));
    }
    // a region at its own instant (to <= from) is never drawn, so it never answers, in either order
    for (const bool zero_first : {false, true}) {
        std::vector<TarTimelineRegion> rs{region(TarRegionKind::exact, W0, W0 + 1000),
                                          region(TarRegionKind::paused, W0 + 1000, W0 + 1000)};
        if (zero_first)
            std::swap(rs[0], rs[1]);
        const auto l = lane("l", "process", "p", {}, rs);
        CHECK(kind_in(l, W0 + 500) == TarRegionKind::exact);
        CHECK(kind_in(l, W0 + 1000) == TarRegionKind::exact);
    }
    CHECK(tar_timeline_region_at(lane("l", "process", "p", {}, {region(TarRegionKind::paused, W0 + 10, W0 + 10)}),
                                 W0 + 10) == nullptr);

    // the moment panel names the region the lane draws, from an unsorted vector
    auto m = with_lane(lane("l", "process", "Processes", {},
                            {region(TarRegionKind::exact, W0 + 100, W1), exact_a, pruned_b}),
                       "G");
    contains(render_timeline_lanes(m), "tl-rg pruned");
    contains(render_timeline_moment(m, W0 + 75, links_full()), "Processes: Nothing is kept for this time");
    lacks(render_timeline_moment(m, W0 + 25, links_full()), "Nothing is kept for this time");
}

TEST_CASE("tar timeline selected: an empty ref selects nothing, an id-less item has no data-ref",
          "[tar][timeline]") {
    auto m = with_lane(lane("l", "process", "p", {bar("", W0 + 100, W0 + 200, "no-id"), bar("x", W0 + 300, W0 + 400)}));
    contains(render_timeline_selected(m, "", W0, links_full()), "That item is not in this read.");
    lacks(render_timeline_selected(m, "", W0, links_full()), "no-id");
    const auto lanes = render_timeline_lanes(m);
    contains(lanes, ">no-id</button>");
    CHECK(count_of(lanes, "data-ref=") == 1); // only "x" can be selected
}

TEST_CASE("tar timeline moment and selected: t == 0 resolves the way the playhead does", "[tar][timeline]") {
    auto m = base();
    m.moment_ts = 0; // resolves to W0 + 3000, where P2 starts
    const auto moment = render_timeline_moment(m, 0, links_full());
    contains(moment, "<b>2026-10-20T09:50:00Z</b>");
    lacks(moment, "\xE2\x80\x94");
    contains(render_timeline_lanes(m), "<b>2026-10-20T09:50:00Z</b>");
    contains(render_timeline_selected(m, "P2", 0, links_full()),
             "href=\"/tar/selected?ref=P1&amp;t=" + std::to_string(W0 + 3000) + "\"");
}

TEST_CASE("tar timeline resolve_moment: a bucket's end is not an event boundary", "[tar][timeline]") {
    auto m = with_lane(lane("L", "dns", "DNS cache",
                            {tick("T", W0 + 2000, "files.example.net"), bucket("BK", W0 + 1500, W0 + 3000, 7)}));
    m.moment_ts = 0;
    CHECK(tar_timeline_resolve_moment(m) == W0 + 2000); // not the bucket's end at W0 + 3000
    const auto html = render_timeline_moment(m, tar_timeline_resolve_moment(m), links_full());
    contains(html, "files.example.net");
    lacks(html, "Nothing at this time");
    // a bucket's start still counts, as a sample's does
    auto starts = with_lane(lane("L", "perf", "CPU", {tick("T", W0 + 1000), column("K", W0 + 1500, W0 + 1530, 5)}));
    starts.moment_ts = 0;
    CHECK(tar_timeline_resolve_moment(starts) == W0 + 1500);
    // a closed bar counts at both ends; an open one at its start only
    auto bars = with_lane(lane("L", "process", "p", {bar("b", W0 + 100, W0 + 900), bar("o", W0 + 400, 0)}));
    bars.moment_ts = 0;
    CHECK(tar_timeline_resolve_moment(bars) == W0 + 900);
}

TEST_CASE("tar timeline caps: facts, links, regions and an unknown tier are bounded and say so",
          "[tar][timeline]") {
    // facts: the first 40 render, then the exact remainder
    auto big = bar("big", W0 + 100, W0 + 200);
    for (int i = 0; i < 41; ++i)
        big.facts.push_back({"k" + std::to_string(i), "v" + std::to_string(i)});
    const auto sel = render_timeline_selected(with_lane(lane("L", "process", "p", {big})), "big", W0, links_full());
    contains(sel, "<span>k39</span>");
    lacks(sel, "<span>k40</span>");
    contains(sel, "<div class=\"tl-none\">and 1 more</div>");
    big.facts.pop_back(); // exactly 40: nothing is dropped, nothing is said
    lacks(render_timeline_selected(with_lane(lane("L", "process", "p", {big})), "big", W0, links_full()), "tl-none");

    // links: the first 24 ids are looked up, then the exact remainder
    std::vector<TarTimelineItem> items;
    auto hub = bar("hub", W0 + 100, W0 + 200);
    for (int i = 0; i < 25; ++i) {
        items.push_back(bar("n" + std::to_string(i), W0 + 300 + i, W0 + 400 + i));
        hub.linked_ids.push_back("n" + std::to_string(i));
    }
    items.push_back(hub);
    const auto linked = render_timeline_selected(with_lane(lane("L", "process", "p", items)), "hub", W0, links_full());
    CHECK(count_of(linked, "<a class=\"btn sm\"") == 24);
    lacks(linked, "ref=n24&amp;");
    contains(linked, "<div class=\"tl-none\">and 1 more</div>");
    items.back().linked_ids.pop_back();
    const auto linked24 = render_timeline_selected(with_lane(lane("L", "process", "p", items)), "hub", W0, links_full());
    CHECK(count_of(linked24, "<a class=\"btn sm\"") == 24);
    lacks(linked24, "tl-none");

    // regions: 400 draw, the rest of the window is one stretch that counts what was left out
    std::vector<TarTimelineRegion> rs;
    for (int i = 0; i < 401; ++i)
        rs.push_back(region(TarRegionKind::pruned, W0 + i * 5, W0 + i * 5 + 5));
    const auto over = render_timeline_lanes(with_lane(lane("L", "process", "p", {}, rs)));
    CHECK(count_of(over, "tl-rg pruned") == 400);
    contains(over, "<b>1 more stretch, not drawn</b>");
    contains(over, "render limit");
    rs.pop_back(); // exactly 400: all drawn, none left out
    const auto exact = render_timeline_lanes(with_lane(lane("L", "process", "p", {}, rs)));
    CHECK(count_of(exact, "tl-rg pruned") == 400);
    lacks(exact, "not drawn");
    lacks(exact, "render limit");
    rs.pop_back(); // 399
    CHECK(count_of(render_timeline_lanes(with_lane(lane("L", "process", "p", {}, rs))), "tl-rg pruned") == 399);

    // an unknown tier is stated as unknown on every surface that names a tier, never clamped
    for (const auto tier : {static_cast<TarTier>(7), static_cast<TarTier>(-1)}) {
        auto m = with_lane(lane("L-dns", "dns", "DNS cache", {bucket("BK", W0, W1, 5, tier)}, {rolled(tier)}),
                           "Network");
        contains(render_timeline_lanes(m), "<b>Roll-up, tier not stated</b>");
        contains(render_timeline_moment(m, W0 + 1800, links_full()),
                 "DNS cache: Roll-up, tier not stated: counts only; exact times are not kept.");
        contains(render_timeline_selected(m, "BK", W0 + 100, links_full()),
                 "<span class=\"pill warn\">Roll-up, tier not stated</span>");
    }
}

// ═══ paused with no reported time ═════════════════════════════════════════════════════

TEST_CASE("tar timeline golden: device bar paused, time not reported", "[tar][timeline][golden]") {
    auto m = base();
    m.sources[4].paused = true; // a pre-0.12.0 agent: paused, no time
    m.sources[2].enabled = false;
    m.sources[2].paused = true; // paused is what is said, not Off
    const auto html = render_timeline_device_bar(m, TarTimelineLinks{});
    check_golden("device-bar__paused-unknown", html);
    contains(html, "Services <span class=\"pill warn\">Paused since a time the agent did not report</span>");
    contains(html, "DNS cache <span class=\"pill warn\">Paused since a time the agent did not report</span>");
    lacks(html, "Services <span class=\"pill ok\">On</span>");
    lacks(html, "\xE2\x80\x94");
}

TEST_CASE("tar timeline golden: kept paused, time not reported", "[tar][timeline][golden]") {
    auto m = kept_model(15 * kDay);
    m.kept[2].paused = true; // the service row of base(): paused, no time
    m.kept[2].paused_since_ts = 0;
    const auto html = render_timeline_kept(m);
    check_golden("kept__paused-unknown", html);
    const auto svc = kept_row_html(html, "service");
    contains(svc, "; paused since a time the agent did not report");
    lacks(svc, "tl-ks none"); // nothing is placed on the axis that the model does not state
    // the moment is decided by the measured bands: a pause it cannot place is not applied
    contains(svc, "<span>Exact records</span>");
    lacks(svc, "Not recorded");
    // a row that is not paused says nothing of it
    lacks(kept_row_html(html, "process"), "paused");
}

TEST_CASE("tar timeline golden: limits paused, time not reported", "[tar][timeline][golden]") {
    auto m = base();
    m.sources[4].paused = true;
    const auto html = render_timeline_limits(m, links_full());
    check_golden("limits__paused-unknown", html);
    limits_always(html);
    contains(html, "Services is paused since a time the agent did not report; its earlier records are kept as they were.");
    contains(html, "href=\"/tar#paused\"");
}

// ═══ css pin ══════════════════════════════════════════════════════════════════════════

TEST_CASE("tar timeline css: one .tl- block, tokens only, no text on a filled highlight",
          "[tar][timeline][css]") {
    const std::string& css = kYuzuCss;
    const std::string marker = "/* -- TAR timeline:";
    const auto start = css.find(marker);
    REQUIRE(start != std::string::npos);
    // Bounded at the next appended block, so a later block's own rules are not scanned here.
    const auto end = css.find("/* -- ", start + marker.size());
    const std::string block = css.substr(start, end == std::string::npos ? std::string::npos : end - start);
    CHECK(count_of(css, marker) == 1);
    for (const char* banned : {"#", "gradient", "var(--accent)", ".dp-", ".tm-", ".split", "blur(", "<style",
                               "url(", "@import"})
        CHECK(count_of(block, banned) == 0);
    contains(block, "color-mix(");
    contains(block, "var(--hl)");
    contains(block, "@media (max-width: 900px)");

    // every selector starts with .tl or is the media rule; no declaration puts a colour on a
    // filled --hl background
    std::size_t pos = block.find('\n') + 1;
    int rules = 0;
    while (pos < block.size()) {
        auto eol = block.find('\n', pos);
        if (eol == std::string::npos)
            eol = block.size();
        const std::string line = block.substr(pos, eol - pos);
        pos = eol + 1;
        if (line.empty() || line.rfind("/*", 0) == 0)
            continue;
        ++rules;
        CHECK((line.rfind(".tl", 0) == 0 || line.rfind("@media", 0) == 0));
        const bool hl_fill = line.find("background: var(--hl)") != std::string::npos ||
                             line.find("background-color: var(--hl)") != std::string::npos;
        const bool text_colour = std::regex_search(line, std::regex("[{;] color:"));
        INFO("rule: " << line);
        CHECK_FALSE((hl_fill && text_colour));
    }
    CHECK(rules > 100);
    // the two time chips sit on the surface with an --hl border
    CHECK(count_of(block, "background: var(--surface); color: var(--ink); border: 1px solid var(--hl);") == 2);

    // The interaction states yuzu-tar-timeline.js toggles: one bounded block, tokens only, every
    // rule a .tl rule (the .tl- block above stops where this one starts, so it is pinned here).
    const std::string open = "/* -- Timeline page interaction states";
    const auto istart = css.find(open);
    REQUIRE(istart != std::string::npos);
    CHECK(count_of(css, open) == 1);
    const auto iend = css.find("/* -- end Timeline page interaction states", istart);
    REQUIRE(iend != std::string::npos);
    const std::string ib = css.substr(istart, iend - istart);
    // touch-action: pan-y keeps vertical page scroll on touch while the scrub owns the horizontal drag.
    for (const char* needle : {".tl-ctl .btn.play[aria-pressed=\"true\"]", ".tl-det.busy", ".tl.scrubbing .tl-body",
                               ".tl-body:focus-visible", ".tl-body { touch-action: pan-y; }", "var(--hl)"})
        contains(ib, needle);
    for (const char* banned : {"#", "gradient", "url(", "@import"})
        CHECK(count_of(ib, banned) == 0);
    std::size_t ipos = ib.find('\n') + 1;
    while (ipos < ib.size()) {
        auto eol = ib.find('\n', ipos);
        if (eol == std::string::npos)
            eol = ib.size();
        const std::string line = ib.substr(ipos, eol - ipos);
        ipos = eol + 1;
        INFO("interaction rule: " << line);
        CHECK((line.empty() || line.rfind(".tl", 0) == 0));
    }
}

// ═══ the markup the page script reads ═════════════════════════════════════════════════

TEST_CASE("tar timeline page contract: the window, the moment and the links are numbers in the markup",
          "[tar][timeline]") {
    const auto m = base();
    const auto lanes = render_timeline_lanes(m);
    contains(lanes, "<div class=\"tl-body\" data-from=\"" + std::to_string(m.window_from_ts) + "\" data-to=\"" +
                        std::to_string(m.window_to_ts) + "\">");
    contains(lanes, "<div class=\"tl-ph\" data-ts=\"" + std::to_string(tar_timeline_resolve_moment(m)) + "\" style=");
    CHECK(count_of(lanes, "data-from=") == 1);
    CHECK(count_of(lanes, "class=\"tl-ph\"") == 1);

    // A window outside the drawable range keeps the attributes on the body (the script rejects
    // it by value) but has no playhead, which is the script's own bind signal.
    auto bad = base();
    bad.window_to_ts = bad.window_from_ts;
    const auto none = render_timeline_lanes(bad);
    contains(none, "data-from=\"" + std::to_string(bad.window_from_ts) + "\" data-to=\"" +
                       std::to_string(bad.window_to_ts) + "\"");
    lacks(none, "class=\"tl-ph\"");

    // Moment panel: Previous / Next carry the adjacent times; a missing side is a disabled button.
    const std::int64_t t = W0 + 1800;
    const auto adj = tar_timeline_adjacent_events(m, t);
    REQUIRE(adj.prev > 0);
    REQUIRE(adj.next > 0);
    const auto moment = render_timeline_moment(m, t, links_full());
    contains(moment, "data-ts=\"" + std::to_string(adj.prev) + "\">Previous event</a>");
    contains(moment, "data-ts=\"" + std::to_string(adj.next) + "\">Next event</a>");
    const auto edge = render_timeline_moment(m, W0, links_full()); // nothing earlier than the window start
    contains(edge, "disabled>Previous event</button>");
    CHECK(count_of(edge, "data-ts=") == 1);
    const auto bare = render_timeline_moment(m, t, TarTimelineLinks{});
    lacks(bare, "data-ts=");

    // Selected panel: each linked-item anchor names the item and the moment it was rendered at.
    const auto sel = render_timeline_selected(m, "P2", W0 + 3300, links_full());
    contains(sel, "data-ref=\"P1\" data-ts=\"" + std::to_string(W0 + 3300) + "\">proc-a.exe 4120</a>");
    CHECK(count_of(sel, "data-ref=") == 1); // "gone-id" is not in the read: dropped
    lacks(render_timeline_selected(m, "P2", W0 + 3300, TarTimelineLinks{}), "data-ref=");

    // A hostile linked id is escaped in the attribute as well as in the href.
    auto h = base();
    h.groups[0].lanes[0].items[0].id = "a\"><x>";
    h.groups[0].lanes[1].items[0].linked_ids = {"a\"><x>"};
    const auto hs = render_timeline_selected(h, "P2", W0 + 3300, links_full());
    contains(hs, "data-ref=\"" + escaped("a\"><x>") + "\"");
    lacks(hs, "<x>");
}

// yuzu-tar-timeline.js repeats two renderer facts as literals (its playheadLeft and edgeClass); the
// node test pins the same strings, so a change on either side fails one of the two suites.
TEST_CASE("tar timeline page contract: the playhead position and the chip edge thresholds",
          "[tar][timeline]") {
    auto m = with_lane(lane("l", "process", "p"));
    m.moment_ts = W0 + 1800; // 50% of the one-hour window
    const auto mid = render_timeline_lanes(m);
    contains(mid, "style=\"left:calc(var(--gut) + (100% - var(--gut)) * 0.50000)\"><b>");
    contains(mid, "style=\"left:calc(var(--gut) + (100% - var(--gut)) * 0.50000 + 1px)\"");
    // fraction of the window -> chip class: past 90% it hangs left ("e"), before 5% right ("s")
    struct Edge {
        std::int64_t at;
        const char* cls;
    };
    for (const auto& e : {Edge{W0 + 3276, " class=\"e\""}, Edge{W0 + 3240, ""}, Edge{W0 + 144, " class=\"s\""},
                          Edge{W0 + 180, ""}}) {
        m.moment_ts = e.at;
        INFO("moment at " << (e.at - W0) << " s of 3600");
        contains(render_timeline_lanes(m), std::string("\"><b") + e.cls + ">");
    }
}
