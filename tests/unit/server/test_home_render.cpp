/// @file test_home_render.cpp
/// Home renderers and pure helpers. Fixtures are built from the value shapes the
/// route hands over (not captured from a live server). No store, clock or process.

#include "home_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cmath>
#include <string>
#include <vector>

using namespace yuzu::server::home;

namespace {

// Fixture builder: the three segments are given, never derived here.
EstateCounts estate(std::int64_t online, std::int64_t not_seen, std::int64_t offline) {
    return EstateCounts{online + not_seen + offline, online, not_seen, offline};
}

bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

constexpr std::int64_t kNow = 1'760'000'000;

SummaryView all_ok() {
    SummaryView v;
    v.now_epoch = kNow;
    v.devices = Fact<EstateCounts>::make_ok(estate(412, 25, 0));
    v.compliance = Fact<ComplianceFigure>::make_ok({4386, 4210, 100, 76, 96.0});
    v.failed = Fact<FailedFigure>::make_ok({14, CountBound::Exact, kNow - 840});
    v.approvals = Fact<ApprovalFigure>::make_ok({2, kNow - 360});
    return v;
}

} // namespace

// ── partitions ─────────────────────────────────────────────────────────────

// ── failed executions ──────────────────────────────────────────────────────

// Kills: reading "100 rows returned" as an exact count (F5), or a short page as capped.
TEST_CASE("failed_in_24h: exact, at-least and capped are distinct", "[home][render]") {
    auto row = [](std::int64_t age) { return FailedRow{kNow - age, kNow - age - 5}; };

    SECTION("short page is exact") {
        const auto f = failed_in_24h({row(60), row(3600), row(90000)}, kNow, 100);
        CHECK(f.count == 2);
        CHECK(f.bound == CountBound::Exact);
        CHECK(f.newest_epoch == kNow - 60);
    }
    SECTION("full page, every row inside the window, is capped") {
        std::vector<FailedRow> rows(100, row(10));
        const auto f = failed_in_24h(rows, kNow, 100);
        CHECK(f.count == 100);
        CHECK(f.bound == CountBound::Capped);
    }
    SECTION("full page spanning past 24 h is a lower bound") {
        std::vector<FailedRow> rows(60, row(10));
        rows.insert(rows.end(), 40, row(200000));
        const auto f = failed_in_24h(rows, kNow, 100);
        CHECK(f.count == 60);
        CHECK(f.bound == CountBound::AtLeast);
    }
    SECTION("completed_at falls back to dispatched_at") {
        const auto f = failed_in_24h({FailedRow{0, kNow - 30}}, kNow, 100);
        CHECK(f.count == 1);
    }
}

// ── small helpers ──────────────────────────────────────────────────────────

TEST_CASE("clamp_pct never leaves 0..100", "[home][render]") {
    CHECK(clamp_pct(-1.0) == 0);
    CHECK(clamp_pct(101.0) == 100);
    CHECK(clamp_pct(1e12) == 100);
    CHECK(clamp_pct(49.6) == 50);
    CHECK(clamp_pct(std::nan("")) == 0);
}

TEST_CASE("compliance_level thresholds are 90 and 70", "[home][render]") {
    CHECK(std::string(compliance_level(90.0)) == "ok");
    CHECK(std::string(compliance_level(89.99)) == "warn");
    CHECK(std::string(compliance_level(70.0)) == "warn");
    CHECK(std::string(compliance_level(69.99)) == "bad");
}

TEST_CASE("fmt_int and hhmm_utc", "[home][render]") {
    CHECK(fmt_int(0) == "0");
    CHECK(fmt_int(999) == "999");
    CHECK(fmt_int(1000) == "1,000");
    CHECK(fmt_int(4386) == "4,386");
    CHECK(fmt_int(1234567) == "1,234,567");
    CHECK(hhmm_utc(0) == "00:00 UTC");
    CHECK(hhmm_utc(3600 * 13 + 60 * 7) == "13:07 UTC");
}

// ── readout ────────────────────────────────────────────────────────────────

TEST_CASE("readout: populated cells carry the real figures and their bases", "[home][render]") {
    const std::string html = render_readout(all_ok());
    CHECK(has(html, "id=\"home-readout\""));
    CHECK(has(html, "<div class=\"v\">412</div>"));
    CHECK(has(html, "of 437 seen in the last 30 days"));
    CHECK(has(html, "25 not seen for 2 days or more"));
    CHECK(has(html, "96%"));
    CHECK(has(html, "4,210 of 4,386 checks"));
    CHECK(has(html, "100 failing, 76 unknown"));
    CHECK(has(html, "in the last 24 hours"));
    CHECK(has(html, "oldest submitted 6m ago"));
    // The returned section must not re-arm its own load trigger.
    CHECK_FALSE(has(html, "hx-get"));
}

// Kills: mapping a degraded read to 0 (false calm).
TEST_CASE("readout: every non-Ok state has its own sentence and never prints 0", "[home][render]") {
    SummaryView v = all_ok();
    v.devices = Fact<EstateCounts>::with(FactState::Denied, "Inventory:Read");
    v.compliance = Fact<ComplianceFigure>::with(FactState::Limited);
    v.failed = Fact<FailedFigure>::with(FactState::Unavailable);
    v.approvals = Fact<ApprovalFigure>::with(FactState::Unwired);
    const std::string html = render_readout(v);
    CHECK(has(html, "It needs <span class=\"mono\">Inventory:Read</span>"));
    CHECK(has(html, "Fleet totals are not shown to accounts limited to a group of devices."));
    CHECK(has(html, "Could not read Executions. This is not zero."));
    CHECK(has(html, "Approvals is not available on this server. This is not zero."));
    CHECK_FALSE(has(html, "<div class=\"v\">0</div>"));
}

TEST_CASE("readout: failed-executions bounds read honestly", "[home][render]") {
    SummaryView v = all_ok();
    v.failed = Fact<FailedFigure>::make_ok({100, CountBound::Capped, kNow});
    CHECK(has(render_readout(v), "100+"));
    v.failed = Fact<FailedFigure>::make_ok({7, CountBound::AtLeast, kNow});
    const std::string html = render_readout(v);
    CHECK(has(html, "at least 7"));
    CHECK(has(html, "Older failures may sit outside the newest 100 read."));
}

TEST_CASE("readout: percent colour follows the 90/70 thresholds and never leaves 0..100",
          "[home][render]") {
    SummaryView v = all_ok();
    v.compliance = Fact<ComplianceFigure>::make_ok({100, 50, 50, 0, 50.0});
    CHECK(has(render_readout(v), "class=\"ro bad\""));
    v.compliance = Fact<ComplianceFigure>::make_ok({100, 80, 20, 0, 80.0});
    CHECK(has(render_readout(v), "class=\"ro warn\""));
    v.compliance = Fact<ComplianceFigure>::make_ok({100, 95, 5, 0, 250.0}); // hostile percent
    const std::string html = render_readout(v);
    CHECK(has(html, "100%"));
    CHECK_FALSE(has(html, "250"));
    v.compliance = Fact<ComplianceFigure>::make_ok({0, 0, 0, 0, 0.0});
    const std::string none = render_readout(v);
    CHECK(has(none, "No results yet")); // never "0%"
    CHECK_FALSE(has(none, "0%"));
}

// ── devices cell ──────────────────────────────────────────────────────────

TEST_CASE("devices cell: empty fleet and each failure state read differently", "[home][render]") {
    SummaryView v = all_ok();
    v.devices = Fact<EstateCounts>::make_ok(EstateCounts{});
    const std::string empty = render_readout(v);
    CHECK(has(empty, "No devices have reported in the last 30 days."));

    v.devices = Fact<EstateCounts>::with(FactState::Unavailable);
    const std::string bad = render_readout(v);
    CHECK(has(bad, "Could not read The device roster. This is not zero."));
    CHECK_FALSE(has(bad, "No devices have reported"));

    v.devices = Fact<EstateCounts>::with(FactState::Unwired);
    const std::string unwired = render_readout(v);
    CHECK(has(unwired, "is not available on this server. This is not zero."));
    CHECK_FALSE(has(unwired, "No devices have reported"));
}

// ── needs attention ───────────────────────────────────────────────────────

TEST_CASE("attention: rows for every contributing figure, with resolved links", "[home][render]") {
    SummaryView v = all_ok();
    v.show_enrolment = true;
    v.enrolment = Fact<std::int64_t>::make_ok(3);
    v.links.approvals = "/approvals";
    v.links.executions = "/executions?status=failed";
    const std::string html = render_attention(v);
    CHECK(has(html, "2 approvals are waiting"));
    CHECK(has(html, "14 executions failed in the last 24 hours"));
    CHECK(has(html, "25 devices have not reported for 2 days or more"));
    CHECK(has(html, "3 agents are awaiting enrolment"));
    CHECK(has(html, "href=\"/approvals\""));
    CHECK(has(html, "href=\"/executions?status=failed\""));
    CHECK_FALSE(has(html, "Nothing needs attention"));
}

TEST_CASE("attention: the green row appears only when every contributor is Ok and empty",
          "[home][render]") {
    SummaryView v = all_ok();
    v.devices = Fact<EstateCounts>::make_ok(estate(10, 0, 0));
    v.failed = Fact<FailedFigure>::make_ok({});
    v.approvals = Fact<ApprovalFigure>::make_ok({});
    CHECK(has(render_attention(v), "Nothing needs attention"));
}

// Kills: rendering the green row while ANY contributor is Denied/Limited/Unavailable (S4);
// every contributor is varied in turn so dropping one contributor's flag is caught.
TEST_CASE("attention: a non-Ok contributor renders a note and no green row", "[home][render]") {
    auto quiet = [] {
        SummaryView v = all_ok();
        v.devices = Fact<EstateCounts>::make_ok(estate(10, 0, 0));
        v.failed = Fact<FailedFigure>::make_ok({});
        v.approvals = Fact<ApprovalFigure>::make_ok({});
        v.show_enrolment = true;
        v.enrolment = Fact<std::int64_t>::make_ok(0);
        return v;
    };
    CHECK(has(render_attention(quiet()), "Nothing needs attention"));

    for (auto s : {FactState::Denied, FactState::Limited, FactState::Unavailable, FactState::Unwired}) {
        INFO(static_cast<int>(s));
        for (int who = 0; who < 4; ++who) {
            SummaryView v = quiet();
            switch (who) {
            case 0: v.devices = Fact<EstateCounts>::with(s, "Inventory:Read"); break;
            case 1: v.failed = Fact<FailedFigure>::with(s, "Execution:Read"); break;
            case 2: v.approvals = Fact<ApprovalFigure>::with(s, "Approval:Read"); break;
            default: v.enrolment = Fact<std::int64_t>::with(s); break;
            }
            const std::string html = render_attention(v);
            INFO("contributor " << who);
            CHECK_FALSE(has(html, "Nothing needs attention"));
            CHECK(has(html, "class=\"note warn\""));
        }
    }
}

TEST_CASE("attention: the enrolment row is omitted for non-admins and never runs the green row on its own",
          "[home][render]") {
    SummaryView v = all_ok();
    v.devices = Fact<EstateCounts>::make_ok(estate(10, 0, 0));
    v.failed = Fact<FailedFigure>::make_ok({});
    v.approvals = Fact<ApprovalFigure>::make_ok({});
    v.show_enrolment = false;
    v.enrolment = Fact<std::int64_t>::make_ok(9); // must be ignored
    const std::string html = render_attention(v);
    CHECK_FALSE(has(html, "awaiting enrolment"));
    CHECK(has(html, "Nothing needs attention"));
}

// ── escaping ──────────────────────────────────────────────────────────────

TEST_CASE("every dynamic string is escaped", "[home][render]") {
    SummaryView v = all_ok();
    v.devices = Fact<EstateCounts>::with(FactState::Denied, "<script>alert(1)</script>:Read");
    v.links.approvals = "/x\" onmouseover=\"alert(1)";
    const std::string html = render_summary(v);
    CHECK_FALSE(has(html, "<script>"));
    CHECK_FALSE(has(html, "\" onmouseover=\""));
    CHECK(has(html, "&lt;script&gt;"));
}

TEST_CASE("summary never carries a device name, agent id or hostname field", "[home][render]") {
    const std::string html = render_summary(all_ok());
    CHECK_FALSE(has(html, "hostname"));
    CHECK_FALSE(has(html, "agent_id"));
    CHECK_FALSE(has(html, "onclick="));
    CHECK_FALSE(has(html, "innerHTML"));
    CHECK_FALSE(has(html, "hx-on"));
}
