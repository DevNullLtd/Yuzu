#include "tar_timeline_render.hpp"

#include "tar_process_tree.hpp" // normalize_tar_os
#include "web_utils.hpp"        // html_escape, format_iso_utc

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <format>
#include <limits>

namespace yuzu::server {

namespace {

// ── small helpers ───────────────────────────────────────────────────────────────────

/// The latest instant the renderer will state or lay out as a time (9999-12-31T23:59:59Z).
/// Past it neither the civil-calendar helpers nor format_iso_utc has a valid answer, so a time
/// beyond it is never computed with or printed.
constexpr std::int64_t kTarTimelineMaxTs = 253402300799;

/// The selected panel shows at most this many engine facts and linked items; the rest are
/// counted ("and N more"), so one runaway item cannot grow the panel without bound.
constexpr std::size_t kMaxSelectedFacts = 40;
constexpr std::size_t kMaxSelectedLinks = 24;

std::string esc(const std::string& s) { return html_escape(s); }

/// A stated time. A time past kTarTimelineMaxTs is said in words, never formatted: the shared
/// formatter prints a zeroed "1900-01-00" for it, which would read as a date. A time <= 0 keeps
/// the formatter's "never" dash.
std::string iso(std::int64_t ts) {
    return ts > kTarTimelineMaxTs ? std::string("a time outside the recordable range")
                                  : format_iso_utc(ts);
}
std::string num(std::int64_t n) { return std::to_string(n); }
std::string fix3(double v) { return std::format("{:.3f}", v); }

std::string plural(std::size_t n, const char* one, const char* many) {
    return std::to_string(n) + " " + (n == 1 ? one : many);
}

std::string lane_label(const TarTimelineLane& l) { return l.name.empty() ? l.id : l.name; }

/// A lane's capped regions folded into one statement: the region with the earliest coverage
/// start (first wins a tie), so the row limit and the date in the sentence come from one read.
/// nullptr when the lane has none. Banner and limits bullet both route through this.
const TarTimelineRegion* lane_cap(const TarTimelineLane& l) {
    const TarTimelineRegion* best = nullptr;
    for (const auto& r : l.regions)
        if (r.kind == TarRegionKind::capped && (!best || r.coverage_from_ts < best->coverage_from_ts))
            best = &r;
    return best;
}

std::string capped_read_text(const TarTimelineLane& l, const TarTimelineRegion& cap) {
    return "The read of " + lane_label(l) + " was cut off at " + num(cap.cap_rows) +
           " rows; nothing before " + iso(cap.coverage_from_ts) + " is shown.";
}

std::string join(const std::vector<std::string>& v, const char* sep) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i)
            out += sep;
        out += v[i];
    }
    return out;
}

/// "31 days", "1 hour", "90 seconds": whole units only, never a rounded figure.
std::string span_text(std::int64_t s) {
    if (s % 86400 == 0)
        return plural(static_cast<std::size_t>(s / 86400), "day", "days");
    if (s % 3600 == 0)
        return plural(static_cast<std::size_t>(s / 3600), "hour", "hours");
    if (s % 60 == 0)
        return plural(static_cast<std::size_t>(s / 60), "minute", "minutes");
    return plural(static_cast<std::size_t>(s), "second", "seconds");
}

constexpr std::array<TarTier, 4> kTiers{TarTier::exact, TarTier::hourly, TarTier::daily,
                                        TarTier::monthly};

/// Per-tier wording, indexed by the (contiguous, 0-based) TarTier value.
///   noun: the unit a record covers ("after each <noun> starts", "whole <noun>")
///   adverb: "exact", "hourly", "daily", "monthly"
///   seg: the kept-chart segment class
struct TierText {
    const char *label, *noun, *adverb, *seg;
};
constexpr std::array<TierText, 4> kTierText{{
    {"Exact records", "record", "exact", "l"},
    {"Hourly roll-up", "hour", "hourly", "h1"},
    {"Daily roll-up", "day", "daily", "h2"},
    {"Monthly roll-up", "month", "monthly", "h3"},
}};
static_assert(static_cast<std::size_t>(TarTier::monthly) + 1 == kTierText.size());

/// A tier value this build does not know (the engine casts an agent-reported byte): said as
/// unknown, never clamped to a real tier.
constexpr TierText kTierUnknown{"Roll-up, tier not stated", "record", "rolled-up", "h3"};

const TierText& tier_text(TarTier t) {
    const auto i = static_cast<std::size_t>(t);
    return i < kTierText.size() ? kTierText[i] : kTierUnknown;
}
std::string tier_label(TarTier t) { return tier_text(t).label; }
std::string tier_noun(TarTier t) { return tier_text(t).noun; }
std::string tier_adverb(TarTier t) { return tier_text(t).adverb; }
std::string tier_seg_class(TarTier t) { return tier_text(t).seg; }

std::string unreadable_text(TarUnreadableReason r) {
    switch (r) {
    case TarUnreadableReason::offline:
        return "device offline";
    case TarUnreadableReason::read_failed:
        return "the read failed";
    case TarUnreadableReason::agent_too_old:
        return "the agent is too old for this read";
    }
    return "device offline";
}

/// The tail every paused sentence shares: "since <ISO>", or in words when the agent did not
/// report when (a pre-0.12.0 agent), never a date placeholder.
std::string paused_since(std::int64_t ts) {
    return ts > 0 ? "since " + iso(ts) : std::string("since a time the agent did not report");
}

/// A source or kept row is paused when it says so, or when it carries a pause time.
template <class T>
bool is_paused(const T& x) {
    return x.paused || x.paused_since_ts > 0;
}

/// What a rolled-up bucket still holds, by source. Never a claim wider than the source.
std::string holdings(const std::string& source, TarTier tier) {
    if (source == "perf")
        return "averages and peaks for the whole " + tier_noun(tier) +
               "; the individual samples are not kept";
    if (source == "process")
        return "counts only; parents, process ids and exact times are not kept";
    return "counts only; exact times are not kept";
}

const TarKeptRow* kept_row_for(const TarTimelineModel& m, const std::string& source) {
    for (const auto& r : m.kept)
        if (r.source == source)
            return &r;
    return nullptr;
}

const TarKeptBand* band_for(const TarKeptRow& row, TarTier tier) {
    for (const auto& b : row.bands)
        if (b.tier == tier)
            return &b;
    return nullptr;
}

/// Retention is stated only from a configured policy or a row limit (the latter for the exact
/// tier only); anything else is not stated, never guessed from measured coverage.
std::string kept_phrase_unknown() { return "How long this is kept is not stated"; }

// ── time ruler labels ───────────────────────────────────────────────────────────────

constexpr std::array<const char*, 12> kMon{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
constexpr std::array<const char*, 7> kDow{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

struct Civil {
    int year;
    unsigned month; // 1..12
    unsigned day;
    unsigned dow; // 0 = Sunday
};

Civil civil(std::int64_t ts) {
    using namespace std::chrono;
    const sys_days d = floor<days>(sys_seconds{seconds{ts}});
    const year_month_day ymd{d};
    return {static_cast<int>(ymd.year()), static_cast<unsigned>(ymd.month()),
            static_cast<unsigned>(ymd.day()), weekday{d}.c_encoding()};
}

std::int64_t month_start(int year, unsigned month) {
    using namespace std::chrono;
    const sys_days d{std::chrono::year{year} / std::chrono::month{month} / 1};
    return static_cast<std::int64_t>(d.time_since_epoch().count()) * 86400;
}

std::string hhmm(std::int64_t ts) {
    const std::int64_t sod = ((ts % 86400) + 86400) % 86400;
    return std::format("{:02}:{:02}", sod / 3600, (sod % 3600) / 60);
}

std::string day_label(std::int64_t ts) {
    const Civil c = civil(ts);
    return std::format("{} {}", c.day, kMon[c.month - 1]);
}

struct Tick {
    std::int64_t ts;
    std::string label;
};

/// Tick step by window span, after the design's tick list: 60 s, 5 min, 2 h, 1 d, 3 d, then
/// month boundaries.
std::vector<Tick> time_ticks(const TarTimelineModel& m) {
    std::vector<Tick> out;
    const std::int64_t from = m.window_from_ts, to = m.window_to_ts;
    // A window outside 1970..9999 draws no ruler (nothing valid can be said about it). Inside it
    // every branch below is bounded by construction: the linear steps yield at most 73 ticks,
    // the month branch has its own guard, and no sum or difference below can overflow.
    if (from <= 0 || to > kTarTimelineMaxTs || to <= from)
        return out;
    const std::int64_t span = to - from;
    auto linear = [&](std::int64_t step, auto label) {
        for (std::int64_t x = (from + step - 1) / step * step; x <= to; x += step)
            out.push_back({x, label(x)});
    };
    if (span <= 1800)
        linear(60, hhmm);
    else if (span <= 6 * 3600)
        linear(300, hhmm);
    else if (span <= 3 * 86400)
        linear(7200, [](std::int64_t x) { return x % 86400 == 0 ? day_label(x) : hhmm(x); });
    else if (span <= 14 * 86400)
        linear(86400, [](std::int64_t x) {
            const Civil c = civil(x);
            return std::format("{} {}", kDow[c.dow], c.day);
        });
    else if (span <= 90 * 86400)
        linear(3 * 86400, day_label);
    else {
        Civil c = civil(from);
        int year = c.year;
        unsigned month = c.month;
        std::int64_t x = month_start(year, month);
        // ponytail: at most 24 monthly ticks bound the output against a bad window (the loop
        // would otherwise walk every month between two arbitrary timestamps); a window past
        // two years draws its first 24 months only. Thin to every Nth month if such windows
        // become real.
        for (int guard = 0; guard < 24 && x <= to; ++guard) {
            if (x >= from) {
                std::string label = kMon[month - 1];
                if (month == 1)
                    label += " " + std::to_string(year);
                out.push_back({x, label});
            }
            if (++month > 12) {
                month = 1;
                ++year;
            }
            x = month_start(year, month);
        }
    }
    return out;
}

// ── shared item geometry ────────────────────────────────────────────────────────────

constexpr std::int64_t kOpenEnd = std::numeric_limits<std::int64_t>::max();

/// The item's end as layout sees it: an open bar runs to kOpenEnd, a tick is a point.
std::int64_t item_end(const TarTimelineItem& it) {
    if (it.shape == TarItemShape::tick)
        return it.from_ts;
    if (it.shape == TarItemShape::bar && it.to_ts == 0)
        return kOpenEnd;
    return std::max(it.to_ts, it.from_ts);
}

bool in_window(const TarTimelineItem& it, const TarTimelineModel& m) {
    const std::int64_t end = item_end(it);
    if (end == it.from_ts) // a point: a tick, or a zero-length item
        return it.from_ts >= m.window_from_ts && it.from_ts <= m.window_to_ts;
    return it.from_ts < m.window_to_ts && end > m.window_from_ts;
}

std::string render_block(const TarTimelineBlock& b) {
    const TarItemShape shape = b.shape;
    std::string h = "<button type=\"button\" class=\"" + b.cls + "\" style=\"left:" +
                    fix3(b.left_pct) + "%";
    if (shape != TarItemShape::tick || b.collapsed)
        h += ";width:" + fix3(b.width_pct) + "%";
    if (shape == TarItemShape::column && !b.collapsed)
        h += ";height:" + num(std::clamp<std::int64_t>(b.count, 0, 100)) + "%";
    h += "\"";
    if (!b.id.empty())
        h += " data-ref=\"" + esc(b.id) + "\"";
    h += " data-ts=\"" + num(b.ts) + "\" title=\"" + esc(b.title) + "\" aria-label=\"" +
         esc(b.title) + "\">";
    if (b.collapsed || shape == TarItemShape::bar || shape == TarItemShape::count)
        h += esc(b.label);
    h += "</button>";
    return h;
}

std::string region_class(const TarTimelineRegion* r) {
    if (!r)
        return "unstated";
    switch (r->kind) {
    case TarRegionKind::exact:
        return "exact";
    case TarRegionKind::rolled_up:
        return "rolled";
    case TarRegionKind::pruned:
        return "pruned";
    case TarRegionKind::paused:
        return "paused";
    case TarRegionKind::not_readable:
        return "unreadable";
    case TarRegionKind::capped:
        return "capped";
    }
    return "unstated";
}

/// The one-line reason a region draws. Empty for exact (nothing is drawn).
std::string region_reason(const TarTimelineRegion& r) {
    switch (r.kind) {
    case TarRegionKind::exact:
        return {};
    case TarRegionKind::rolled_up:
        return tier_label(r.tier);
    case TarRegionKind::pruned:
        return "Pruned";
    case TarRegionKind::paused:
        return "Paused " + paused_since(r.paused_since_ts);
    case TarRegionKind::not_readable:
        return "Not readable: " + unreadable_text(r.reason);
    case TarRegionKind::capped:
        return "Record cut off at " + num(r.cap_rows) + " rows; showing from " +
               iso(r.coverage_from_ts);
    }
    return {};
}

std::string region_div(const std::string& cls, double left, double width,
                       const std::string& reason) {
    return "<div class=\"tl-rg " + cls + "\" style=\"left:" + fix3(left) + "%;width:" +
           fix3(width) + "%\"><b>" + esc(reason) + "</b></div>";
}

/// Regions as drawn: model regions clipped to the window, with a `.unstated` stretch for
/// every part of the window no region covers. Exact regions draw nothing but are covered. At
/// most kTarTimelineMaxBlocksPerLane regions draw (by start time); `omitted` is how many more
/// there were, and the rest of the window is one `.unstated` stretch that says so.
std::string render_regions(const TarTimelineLane& lane, const TarTimelineModel& m,
                           std::size_t& omitted) {
    std::vector<const TarTimelineRegion*> rs;
    for (const auto& r : lane.regions)
        if (r.to_ts > r.from_ts && r.to_ts > m.window_from_ts && r.from_ts < m.window_to_ts)
            rs.push_back(&r);
    std::stable_sort(rs.begin(), rs.end(), [](const auto* a, const auto* b) {
        return a->from_ts < b->from_ts;
    });
    omitted = rs.size() > kTarTimelineMaxBlocksPerLane ? rs.size() - kTarTimelineMaxBlocksPerLane : 0;
    rs.resize(rs.size() - omitted);
    std::string h;
    std::int64_t cursor = m.window_from_ts;
    auto gap = [&](std::int64_t a, std::int64_t b, const std::string& why = "Coverage not stated") {
        const double l = tar_timeline_pct(m, a);
        h += region_div("unstated", l, tar_timeline_pct(m, b) - l, why);
    };
    for (const auto* r : rs) {
        const std::int64_t a = std::max(r->from_ts, m.window_from_ts);
        const std::int64_t b = std::min(r->to_ts, m.window_to_ts);
        if (a > cursor)
            gap(cursor, a);
        if (r->kind != TarRegionKind::exact) {
            const double l = tar_timeline_pct(m, a);
            h += region_div(region_class(r), l, tar_timeline_pct(m, b) - l, region_reason(*r));
        }
        cursor = std::max(cursor, b);
    }
    if (cursor < m.window_to_ts)
        gap(cursor, m.window_to_ts,
            omitted > 0 ? plural(omitted, "more stretch", "more stretches") + ", not drawn"
                        : "Coverage not stated");
    return h;
}

/// "calc(var(--gut) + (100% - var(--gut)) * f)": a position on the plot area, which starts
/// after the label gutter. f is renderer-computed, never model text.
std::string plot_left(double f, const char* plus = "") {
    return "left:calc(var(--gut) + (100% - var(--gut)) * " + std::format("{:.5f}", f) + plus + ")";
}

// ── kept chart ──────────────────────────────────────────────────────────────────────

/// The design's log age axis: 0 at "now", 1 at 480 days (the registry's 365-day monthly default
/// plus headroom, so the oldest band never sits on the axis edge).
double age_axis(double age_s) {
    constexpr double kHour = 3600.0, kAxMax = 480.0 * 86400.0;
    return std::clamp(std::log1p(std::max(age_s, 0.0) / kHour) / std::log1p(kAxMax / kHour), 0.0, 1.0);
}

/// How old `ts` is at `read_ts`, in seconds. Subtracted as doubles: both are agent-controlled
/// and an int64 difference of two of them can overflow.
double age_of(std::int64_t read_ts, std::int64_t ts) {
    return std::max(static_cast<double>(read_ts) - static_cast<double>(ts), 0.0);
}

std::string kept_qualifier(const TarKeptRow& row, const TarKeptBand* band, TarTier tier) {
    if (tier == TarTier::exact && row.row_limit > 0)
        return "kept until newer rows push it out";
    if (band && band->policy_s > 0)
        return "pruned " + span_text(band->policy_s) + " after each " + tier_noun(tier) +
               " starts, at the earliest";
    return kept_phrase_unknown();
}

struct AtMoment {
    std::string res, sub;
    bool gone = false;
};

AtMoment kept_at_moment(const TarTimelineModel& m, const TarKeptRow& row, std::int64_t moment) {
    // A pause with no stated time cannot be placed against the moment, so it is not applied
    // here; the measured bands decide and kept_row_sub says the source is paused.
    if (row.paused_since_ts > 0 && moment >= row.paused_since_ts)
        return {"Not recorded", "Source paused " + paused_since(row.paused_since_ts), false};
    // Not readable is not Gone: neither the word nor the faint `.gone` style, which says
    // "nothing is here".
    if (!m.online)
        return {"Not readable: device offline", {}, false};
    if (row.unreadable)
        return {"Not readable: " + unreadable_text(*row.unreadable), {}, false};
    for (TarTier t : kTiers) {
        const TarKeptBand* b = band_for(row, t);
        if (b && b->oldest_ts > 0 && moment >= b->oldest_ts)
            return {tier_label(t), kept_qualifier(row, b, t), false};
    }
    return {"Gone: nothing is kept this far back", {}, true};
}

std::string kept_row_sub(const TarKeptRow& row) {
    const TarKeptBand* ex = band_for(row, TarTier::exact);
    std::string s;
    if (row.row_limit > 0) {
        s = num(row.row_limit) + " rows kept";
        if (ex && ex->oldest_ts > 0)
            s += "; exact records reach back to " + iso(ex->oldest_ts) + " on this device";
    } else if (ex && ex->policy_s > 0) {
        s = "kept " + span_text(ex->policy_s) + " by default";
    } else {
        s = kept_phrase_unknown();
    }
    // A known pause time is drawn as the "not recorded" segment; an unknown one cannot be
    // placed on the axis, so it is said here instead.
    if (row.paused && row.paused_since_ts <= 0)
        s += "; paused " + paused_since(0);
    return s;
}

std::string kept_segments(const TarTimelineModel& m, const TarKeptRow& row) {
    std::string h;
    auto seg = [&](const std::string& cls, double a, double b, const std::string& tip,
                   const std::string& text) {
        const double l = age_axis(a) * 100.0;
        h += "<div class=\"tl-ks " + cls + "\" style=\"left:" + fix3(l) + "%;width:" +
             fix3(age_axis(b) * 100.0 - l) + "%\" title=\"" + esc(tip) + "\">" + esc(text) +
             "</div>";
    };
    double start = 0;
    if (row.paused_since_ts > 0) { // an unstated pause time cannot be placed: no segment
        const double pa = age_of(m.read_ts, row.paused_since_ts);
        if (pa > 0) {
            seg("none", 0, pa, "Nothing recorded " + paused_since(row.paused_since_ts),
                "not recorded");
            start = pa;
        }
    }
    for (TarTier t : kTiers) {
        const TarKeptBand* b = band_for(row, t);
        if (!b || b->oldest_ts <= 0)
            continue; // none observed: draws nothing
        const double end = age_of(m.read_ts, b->oldest_ts);
        if (end <= start)
            continue; // the newer tier already covers this far back
        seg(tier_seg_class(t), start, end, tier_label(t) + ", oldest observed " + iso(b->oldest_ts),
            tier_adverb(t));
        start = end;
    }
    return h;
}

// ── moment panel ────────────────────────────────────────────────────────────────────

struct StateLine {
    std::string key;
    std::string text;
    std::vector<std::string> names;
};

std::string holdings_category(const std::string& source) {
    return source == "perf" || source == "process" ? source : "other";
}

/// The sentence for a lane whose region at t is not exact. `r` null = coverage not stated.
std::pair<std::string, std::string> state_for(const TarTimelineLane& lane,
                                              const TarTimelineRegion* r) {
    if (!r)
        return {"unstated", "Coverage not stated"};
    switch (r->kind) {
    case TarRegionKind::exact:
        return {"exact-none", "Nothing at this time"};
    case TarRegionKind::rolled_up:
        return {"rolled|" + num(static_cast<int>(r->tier)) + "|" + holdings_category(lane.source),
                tier_label(r->tier) + ": " + holdings(lane.source, r->tier) + "."};
    case TarRegionKind::pruned:
        return {"pruned", "Nothing is kept for this time"};
    case TarRegionKind::paused:
        return {"paused|" + num(r->paused_since_ts),
                "Not recorded " + paused_since(r->paused_since_ts)};
    case TarRegionKind::not_readable:
        return {"unreadable|" + num(static_cast<int>(r->reason)),
                "Not readable: " + unreadable_text(r->reason)};
    case TarRegionKind::capped:
        return {"capped|" + num(r->cap_rows) + "|" + num(r->coverage_from_ts),
                "The read was cut off at " + num(r->cap_rows) + " rows; nothing before " +
                    iso(r->coverage_from_ts) + " is shown"};
    }
    return {"unstated", "Coverage not stated"};
}

struct MomentRow {
    std::string name, lane, age;
    bool bad = false;
};

std::string moment_nav(const char* label, std::int64_t ts, const TarTimelineLinks& links) {
    if (links.moment && ts > 0)
        return std::string("<a class=\"btn sm\" href=\"") + esc(links.moment(ts)) + "\">" + label +
               "</a>";
    return std::string("<button type=\"button\" class=\"btn sm\" disabled>") + label + "</button>";
}

// ── selected panel ──────────────────────────────────────────────────────────────────

struct Found {
    const TarTimelineLane* lane = nullptr;
    const TarTimelineItem* item = nullptr;
};

/// The first item with this id. An empty id matches nothing: such an item has no `data-ref`, so
/// nothing on the page can select it. Ids are unique across the model by contract (see
/// TarTimelineItem); the renderer cannot know which of two same-id items was meant.
Found find_item(const TarTimelineModel& m, const std::string& id) {
    if (id.empty())
        return {};
    for (const auto& g : m.groups)
        for (const auto& l : g.lanes)
            for (const auto& it : l.items)
                if (it.id == id)
                    return {&l, &it};
    return {};
}

std::string retention_line(const TarTimelineModel& m, const TarTimelineLane& lane,
                           const TarTimelineItem& it) {
    const TarKeptRow* row = kept_row_for(m, lane.source);
    const TarKeptBand* band = row ? band_for(*row, it.tier) : nullptr;
    if (row && it.tier == TarTier::exact && row->row_limit > 0)
        return "Kept until newer rows push it past the " + num(row->row_limit) +
               "-row limit; no date can be given";
    if (band && band->policy_s > 0) {
        // No date is stated rather than a wrapped or out-of-range one: from_ts is agent data, so
        // the sum is only formed when it provably stays inside 1970..9999 (and cannot overflow).
        if (it.from_ts <= 0 || band->policy_s > kTarTimelineMaxTs - it.from_ts)
            return "Pruned " + span_text(band->policy_s) + " after it starts, at the earliest";
        const char* unit = it.shape == TarItemShape::count || it.shape == TarItemShape::column
                               ? "bucket"
                               : "record";
        return "Pruned after " + iso(it.from_ts + band->policy_s) + " at the earliest (a " + unit +
               " ages from its start; the agent prunes on its own tick and may hold it longer)";
    }
    return kept_phrase_unknown();
}

} // namespace

// ── layout ──────────────────────────────────────────────────────────────────────────

double tar_timeline_pct(const TarTimelineModel& m, std::int64_t ts) {
    // All in double: the window and ts are agent-controlled, and an int64 difference of two of
    // them can overflow. A degenerate or inverted window yields 0.
    const double from = static_cast<double>(m.window_from_ts);
    const double to = static_cast<double>(m.window_to_ts);
    if (to <= from)
        return 0.0;
    return std::clamp((static_cast<double>(ts) - from) * 100.0 / (to - from), 0.0, 100.0);
}

TarTimelineLayout tar_timeline_layout_lane(const TarTimelineLane& lane, const TarTimelineModel& m) {
    TarTimelineLayout out;
    if (m.window_to_ts <= m.window_from_ts)
        return out;

    struct Pre {
        const TarTimelineItem* it;
        double left, end;
        double width() const { return end - left; }
    };
    std::vector<Pre> pre;
    for (const auto& it : lane.items) {
        if (!in_window(it, m))
            continue;
        const std::int64_t end_ts = std::min(item_end(it), m.window_to_ts);
        pre.push_back({&it, tar_timeline_pct(m, it.from_ts), tar_timeline_pct(m, end_ts)});
    }
    std::stable_sort(pre.begin(), pre.end(),
                     [](const Pre& a, const Pre& b) { return a.it->from_ts < b.it->from_ts; });

    auto make_block = [&](const Pre& p) {
        const TarTimelineItem& it = *p.it;
        TarTimelineBlock b;
        b.left_pct = p.left;
        b.width_pct = std::max(p.width(), kTarTimelineMinWidthPct);
        b.label = it.label;
        b.title = it.title.empty() ? (it.label.empty() ? it.id : it.label) : it.title;
        b.id = it.id;
        b.count = it.count;
        b.ts = it.from_ts;
        b.shape = it.shape;
        const bool cl = it.from_ts < m.window_from_ts;
        const bool cr = it.shape != TarItemShape::tick &&
                        (item_end(it) == kOpenEnd || item_end(it) > m.window_to_ts);
        const char* tone = lane.source == "tcp" ? " net" : (lane.source == "user" ? " ses" : "");
        switch (it.shape) {
        case TarItemShape::bar:
            b.cls = std::string("tl-b") + tone + (it.flagged ? " bad" : "");
            break;
        case TarItemShape::count:
            b.cls = std::string("tl-c") + (lane.source == "tcp" ? " net" : "") +
                    (it.flagged ? " bad" : "");
            break;
        case TarItemShape::tick:
            b.cls = std::string("tl-t") + (it.flagged ? " bad" : "");
            break;
        case TarItemShape::column:
            b.cls = std::string("tl-k") + (it.flagged ? " hi" : "");
            break;
        }
        if (it.shape == TarItemShape::bar || it.shape == TarItemShape::count) {
            if (cl)
                b.cls += " cl";
            if (cr)
                b.cls += " cr";
        }
        return b;
    };

    auto collapse = [&](std::size_t from, std::size_t to) {
        TarTimelineBlock b;
        double end = pre[from].end;
        std::int64_t events = 0;
        for (std::size_t i = from; i < to; ++i) {
            end = std::max(end, pre[i].end);
            events += pre[i].it->count;
        }
        const std::size_t n = to - from;
        switch (pre[from].it->shape) {
        case TarItemShape::bar:
        case TarItemShape::tick:
            b.label = num(static_cast<std::int64_t>(n)) + " events";
            break;
        case TarItemShape::count:
            b.label = num(static_cast<std::int64_t>(n)) + " buckets, " + num(events) + " events";
            break;
        case TarItemShape::column:
            b.label = num(static_cast<std::int64_t>(n)) + " samples";
            break;
        }
        b.cls = "tl-d";
        b.title = b.label;
        b.left_pct = pre[from].left;
        b.width_pct = std::max(end - pre[from].left, kTarTimelineMinWidthPct);
        b.count = static_cast<std::int64_t>(n);
        b.ts = pre[from].it->from_ts;
        b.items = n;
        b.shape = pre[from].it->shape;
        b.collapsed = true;
        return b;
    };

    std::size_t run = 0;
    bool in_run = false;
    auto flush = [&](std::size_t upto) {
        if (upto - run >= kTarTimelineCollapseMin)
            out.blocks.push_back(collapse(run, upto));
        else
            for (std::size_t i = run; i < upto; ++i)
                out.blocks.push_back(make_block(pre[i]));
    };
    for (std::size_t i = 0; i < pre.size(); ++i) {
        const bool tiny = pre[i].width() < kTarTimelineMinBlockPct;
        if (in_run && tiny && pre[i].it->shape == pre[run].it->shape &&
            pre[i].left - pre[i - 1].end <= kTarTimelineMinBlockPct)
            continue;
        if (in_run)
            flush(i);
        in_run = tiny;
        if (tiny)
            run = i;
        else
            out.blocks.push_back(make_block(pre[i]));
    }
    if (in_run)
        flush(pre.size());

    if (out.blocks.size() > kTarTimelineMaxBlocksPerLane) {
        out.overflow_left_pct = out.blocks[kTarTimelineMaxBlocksPerLane].left_pct;
        for (std::size_t i = kTarTimelineMaxBlocksPerLane; i < out.blocks.size(); ++i)
            out.overflow_count += out.blocks[i].items;
        out.blocks.resize(kTarTimelineMaxBlocksPerLane);
    }
    return out;
}

const TarTimelineRegion* tar_timeline_region_at(const TarTimelineLane& lane, std::int64_t t) {
    // Only regions the lane draws count (render_regions drops to_ts <= from_ts). Where regions
    // overlap, the one drawn on top wins: the stable sort by start paints a later start over an
    // earlier one, and a tie goes to the later region in vector order.
    auto drawn = [](const TarTimelineRegion& r) { return r.to_ts > r.from_ts; };
    auto on_top = [](const TarTimelineRegion& r, const TarTimelineRegion* best) {
        return !best || r.from_ts >= best->from_ts;
    };
    std::int64_t last_end = std::numeric_limits<std::int64_t>::min();
    for (const auto& r : lane.regions)
        if (drawn(r))
            last_end = std::max(last_end, r.to_ts);
    const TarTimelineRegion* best = nullptr;
    for (const auto& r : lane.regions)
        if (drawn(r) && r.from_ts <= t && t < r.to_ts && on_top(r, best))
            best = &r;
    if (best)
        return best;
    for (const auto& r : lane.regions) // the last region is closed at its end
        if (drawn(r) && r.to_ts == last_end && r.from_ts <= t && t == r.to_ts && on_top(r, best))
            best = &r;
    return best;
}

std::vector<const TarTimelineItem*> tar_timeline_items_at(const TarTimelineLane& lane,
                                                          std::int64_t t) {
    std::vector<const TarTimelineItem*> out, ticks;
    for (const auto& it : lane.items) {
        switch (it.shape) {
        case TarItemShape::bar:
            if (it.from_ts <= t && (it.to_ts == 0 || t < it.to_ts))
                out.push_back(&it);
            break;
        case TarItemShape::tick:
            if (it.from_ts <= t)
                ticks.push_back(&it);
            break;
        case TarItemShape::count:
        case TarItemShape::column:
            if (it.from_ts <= t && t < it.to_ts)
                out.push_back(&it);
            break;
        }
    }
    std::stable_sort(ticks.begin(), ticks.end(),
                     [](const auto* a, const auto* b) { return a->from_ts > b->from_ts; });
    out.insert(out.end(), ticks.begin(), ticks.end());
    return out;
}

TarTimelineAdjacent tar_timeline_adjacent_events(const TarTimelineModel& m, std::int64_t t) {
    TarTimelineAdjacent adj;
    auto consider = [&](std::int64_t b) {
        if (b <= 0 || b < m.window_from_ts || b > m.window_to_ts)
            return;
        if (b < t && (adj.prev == 0 || b > adj.prev))
            adj.prev = b;
        if (b > t && (adj.next == 0 || b < adj.next))
            adj.next = b;
    };
    for (const auto& g : m.groups)
        for (const auto& l : g.lanes)
            for (const auto& it : l.items) {
                if (it.shape == TarItemShape::bar) {
                    consider(it.from_ts);
                    if (it.to_ts != 0)
                        consider(it.to_ts);
                } else if (it.shape == TarItemShape::tick) {
                    consider(it.from_ts);
                }
            }
    return adj;
}

std::int64_t tar_timeline_resolve_moment(const TarTimelineModel& m) {
    auto inside = [&](std::int64_t t) { return t >= m.window_from_ts && t <= m.window_to_ts; };
    if (m.moment_ts != 0 && inside(m.moment_ts))
        return m.moment_ts;
    // The newest event boundary: every item's start, and a closed bar's end. A bucket or sample
    // end is not one (items_at treats it as exclusive, so nothing would be listed there).
    std::int64_t newest = 0;
    auto consider = [&](std::int64_t b) {
        if (b > 0 && inside(b))
            newest = std::max(newest, b);
    };
    for (const auto& g : m.groups)
        for (const auto& l : g.lanes)
            for (const auto& it : l.items) {
                consider(it.from_ts);
                if (it.shape == TarItemShape::bar)
                    consider(it.to_ts);
            }
    return newest != 0 ? newest : m.window_to_ts;
}

// ── device bar ──────────────────────────────────────────────────────────────────────

std::string render_timeline_device_bar(const TarTimelineModel& m, const TarTimelineLinks& links) {
    const std::string name = !m.hostname.empty()    ? m.hostname
                             : !m.agent_id.empty() ? m.agent_id
                                                    : std::string("Unknown device");
    std::string h = "<div class=\"tl-host\"><span class=\"n\">" + esc(name) + "</span>";
    h += m.online ? "<span class=\"pill ok\">Online</span>" : "<span class=\"pill idle\">Offline</span>";
    if (!m.os.empty())
        h += "<span class=\"m\"><b>" + esc(m.os) + "</b></span>";
    if (!links.choose_device.empty())
        h += "<a class=\"btn sm\" href=\"" + esc(links.choose_device) + "\">Choose another device</a>";
    if (!links.device.empty())
        h += "<a class=\"btn sm\" href=\"" + esc(links.device) + "\">Open device</a>";
    h += "<span class=\"src\">";
    for (const auto& s : m.sources) {
        const std::string label = s.label.empty() ? s.source : s.label;
        std::string chip;
        if (is_paused(s))
            chip = "<span class=\"pill warn\">Paused " + esc(paused_since(s.paused_since_ts)) +
                   "</span>";
        else if (s.enabled)
            chip = "<span class=\"pill ok\">On</span>";
        else
            chip = "<span class=\"pill idle\">Off</span>";
        h += "<span>" + esc(label) + " " + chip + "</span>";
    }
    h += "</span></div>";
    return h;
}

// ── kept chart ──────────────────────────────────────────────────────────────────────

std::string render_timeline_kept(const TarTimelineModel& m) {
    const std::int64_t moment = tar_timeline_resolve_moment(m);
    constexpr std::array<std::pair<std::int64_t, const char*>, 6> kAxis{{{0, "now"},
                                                                           {3600, "1 hour"},
                                                                           {86400, "1 day"},
                                                                           {7 * 86400, "1 week"},
                                                                           {31 * 86400, "1 month"},
                                                                           {365 * 86400, "1 year"}}};
    std::string ticks, grid;
    for (const auto& [age, label] : kAxis) {
        const double x = age_axis(static_cast<double>(age)) * 100.0;
        ticks += std::string("<span class=\"tl-ktk") + (x > 90.0 ? " end" : "") +
                 "\" style=\"left:" + fix3(x) + "%\">" + label + "</span>";
        grid += "<i style=\"left:" + fix3(x) + "%\"></i>";
    }
    std::string h = "<div class=\"tl-kp\">";
    h += "<div class=\"tl-kr tl-kax\"><div class=\"lab\">Age of the record</div><div class=\"pl\">" +
         ticks + "</div><div class=\"res\">At the moment</div></div>";
    h += "<div class=\"tl-kov\">" + grid + "</div>";
    h += "<div class=\"tl-kr sec\"><div class=\"lab\">On the device. Needs it online.</div></div>";
    for (const auto& row : m.kept) {
        const AtMoment at = kept_at_moment(m, row, moment);
        h += "<div class=\"tl-kr\" data-source=\"" + esc(row.source) + "\"><div class=\"lab\"><b>" +
             esc(row.label.empty() ? row.source : row.label) + "</b><small>" +
             esc(kept_row_sub(row)) + "</small></div><div class=\"pl\">" + kept_segments(m, row) +
             "</div><div class=\"res" + (at.gone ? " gone" : "") + "\"><span>" + esc(at.res) +
             "</span>" + (at.sub.empty() ? "" : "<small>" + esc(at.sub) + "</small>") + "</div></div>";
    }
    const double mx = age_axis(age_of(m.read_ts, moment)) * 100.0;
    h += "<div class=\"tl-kov\"><div class=\"tl-kmk\" style=\"left:" + fix3(mx) + "%\"><b" +
         (mx > 55.0 ? " class=\"r\"" : "") + ">" + esc(iso(moment)) + "</b></div></div>";
    h += "</div>";
    h += "<div class=\"tl-kleg\" aria-label=\"Key\"><span><i class=\"l\"></i>Exact records</span>"
         "<span><i class=\"h1\"></i>Hourly roll-up</span><span><i class=\"h2\"></i>Daily roll-up</span>"
         "<span><i class=\"h3\"></i>Monthly roll-up</span><span>Nothing after the bar: pruned</span></div>";
    h += "<p class=\"tl-knote\">The limits are the agent's defaults. Coverage is measured on this "
         "device: each bar reaches back to the oldest record the device holds. The agent prunes on "
         "its own tick and can decline a prune when its clock looks wrong, so records may outlive "
         "these limits. A roll-up keeps counts or averages, not the events.</p>";
    return h;
}

// ── lanes ───────────────────────────────────────────────────────────────────────────

std::string render_timeline_lanes(const TarTimelineModel& m) {
    std::string h;
    std::vector<TarTimelineLayout> layouts;
    std::vector<std::string> region_html; // per lane, in drawing order
    bool hit_limit = false;
    for (const auto& g : m.groups)
        for (const auto& l : g.lanes) {
            layouts.push_back(tar_timeline_layout_lane(l, m));
            std::size_t omitted = 0;
            region_html.push_back(render_regions(l, m, omitted));
            hit_limit = hit_limit || layouts.back().overflow_count > 0 || omitted > 0;
        }

    // Banners first: a cut-off or unreadable read is said before any lane is drawn.
    if (m.window_to_ts <= m.window_from_ts)
        h += "<div class=\"tl-warn\">The time window is not valid: it ends before it starts, so "
             "nothing can be drawn.</div>";
    if (!m.online)
        h += "<div class=\"tl-warn\">Device offline: on-device records are not readable.</div>";
    std::vector<std::string> unreadable_seen; // one banner per distinct (lane, reason)
    for (const auto& g : m.groups)
        for (const auto& l : g.lanes) {
            if (const auto* cap = lane_cap(l)) // one banner per lane, however many capped stretches
                h += "<div class=\"tl-warn\">" + esc(capped_read_text(l, *cap)) + "</div>";
            for (const auto& r : l.regions) {
                // An offline device already said so above; repeating it per lane is noise.
                if (r.kind != TarRegionKind::not_readable ||
                    (!m.online && r.reason == TarUnreadableReason::offline))
                    continue;
                const std::string key = lane_label(l) + "|" + num(static_cast<int>(r.reason));
                if (std::find(unreadable_seen.begin(), unreadable_seen.end(), key) !=
                    unreadable_seen.end())
                    continue;
                unreadable_seen.push_back(key);
                h += "<div class=\"tl-warn\">" + esc(lane_label(l)) + " could not be read: " +
                     esc(unreadable_text(r.reason)) + ".</div>";
            }
        }
    if (hit_limit)
        h += "<div class=\"tl-warn\">A lane has more items or stretches than the render limit (" +
             num(static_cast<std::int64_t>(kTarTimelineMaxBlocksPerLane)) +
             " per lane); the rest are counted but not drawn. Narrow the window.</div>";

    const auto ticks = time_ticks(m);
    h += "<div class=\"tl\"><div class=\"tl-head\"><div class=\"g\">Time (UTC)</div><div class=\"r\">";
    for (const auto& t : ticks)
        h += "<span class=\"tl-tk\" style=\"left:" + fix3(tar_timeline_pct(m, t.ts)) + "%\">" +
             esc(t.label) + "</span>";
    h += "</div></div><div class=\"tl-grid\">";
    for (const auto& t : ticks)
        h += "<i style=\"left:" + fix3(tar_timeline_pct(m, t.ts)) + "%\"></i>";
    h += "</div><div class=\"tl-body\">";
    if (m.groups.empty())
        h += "<div class=\"tl-empty\">No lanes in this read.</div>";

    std::size_t li = 0;
    for (const auto& g : m.groups) {
        h += "<div class=\"tl-row sec\"><div class=\"lab\"><span class=\"ln\"><span class=\"nm\">" +
             esc(g.name.empty() ? std::string("Lanes") : g.name) +
             "</span></span></div><div class=\"pl\"></div></div>";
        for (const auto& l : g.lanes) {
            const TarTimelineLayout& lay = layouts[li++];
            bool column = false;
            for (const auto& it : l.items)
                column = column || it.shape == TarItemShape::column;
            std::string cls = "tl-row";
            if (l.flagged)
                cls += " bad";
            if (column)
                cls += " tall";
            if (l.depth > 0)
                cls += " d" + num(std::min(l.depth, 6));
            h += "<div class=\"" + cls + "\" data-lane=\"" + esc(l.id) + "\" data-source=\"" +
                 esc(l.source) + "\"><div class=\"lab\"><span class=\"ln\"><span class=\"nm\">" +
                 esc(l.name.empty() ? l.id : l.name) + "</span>";
            if (!l.sub.empty())
                h += "<span class=\"pid\">" + esc(l.sub) + "</span>";
            h += "</span></div><div class=\"pl\">" + region_html[li - 1];
            for (const auto& b : lay.blocks)
                h += render_block(b);
            if (lay.overflow_count > 0) {
                const std::string label = plural(lay.overflow_count, "more item", "more items") +
                                          ", not drawn";
                h += "<span class=\"tl-d\" style=\"left:" + fix3(lay.overflow_left_pct) +
                     "%;width:" + fix3(std::max(100.0 - lay.overflow_left_pct, kTarTimelineMinWidthPct)) +
                     "%\" title=\"" + esc(label) + "\">" + esc(label) + "</span>";
            }
            h += "</div></div>";
        }
    }
    h += "</div>";

    const std::int64_t moment = tar_timeline_resolve_moment(m);
    const double f = tar_timeline_pct(m, moment) / 100.0;
    h += "<div class=\"tl-fut\" style=\"" + plot_left(f, " + 1px") + "\"></div>";
    h += "<div class=\"tl-ph\" style=\"" + plot_left(f) + "\"><b" +
         (f > 0.9 ? " class=\"e\"" : (f < 0.05 ? " class=\"s\"" : "")) + ">" + esc(iso(moment)) +
         "</b></div></div>";
    return h;
}

// ── limits ──────────────────────────────────────────────────────────────────────────

std::string render_timeline_limits(const TarTimelineModel& m, const TarTimelineLinks& links) {
    std::vector<std::string> items; // plain text; escaped at emission
    items.push_back("There is no starting snapshot: TAR records what it sees from the time it was "
                    "switched on, so what was already running then has no recorded start.");
    items.push_back(m.poll_interval_s && *m.poll_interval_s > 0
                        ? "The record is read every " + num(*m.poll_interval_s) +
                              " seconds, not continuously."
                        : std::string("The record is read on the agent's polling interval, not "
                                      "continuously."));
    if (m.process_capture_method == "etw")
        items.push_back("Process starts and stops come from the Windows ETW event stream as of "
                        "this read; a stretch recorded while the agent had fallen back to polling "
                        "carries snapshot times.");
    else if (m.process_capture_method == "endpoint_security")
        items.push_back("Process starts and stops come from the Endpoint Security event stream as "
                        "of this read; a stretch recorded while the agent had fallen back to "
                        "polling carries snapshot times.");
    else if (m.process_capture_method == "polling")
        items.push_back("Processes are read on the agent's polling interval; a process that starts "
                        "and exits between reads is missed, and start times are snapshot times.");
    else // empty or unrecognised: the method is unknown, said so and no mechanism is claimed
        items.push_back("The agent did not state how processes are captured. If it polls, a "
                        "process that starts and exits between reads is missed and start times "
                        "are snapshot times.");
    const std::string os = normalize_tar_os(m.os);
    if (os == "windows" || os == "macos") {
        // Neither the event streams nor a poll store arguments, so that much holds on every
        // path; what else is recorded depends on the live capture method, never on the OS: the
        // streams give names only, a poll stores the executable's path.
        std::string s = std::string("Command lines are not recorded on ") +
                        (os == "windows" ? "Windows" : "macOS");
        if (m.process_capture_method == "etw" || m.process_capture_method == "endpoint_security")
            s += "; process names only";
        else if (m.process_capture_method == "polling")
            s += "; the executable's path is recorded, not its arguments";
        items.push_back(s + ".");
    }
    bool dns = false;
    for (const auto& s : m.sources)
        dns = dns || s.source == "dns";
    for (const auto& g : m.groups)
        for (const auto& l : g.lanes)
            dns = dns || l.source == "dns";
    if (dns)
        items.push_back("The DNS cache does not say which process asked.");
    items.push_back("TAR does not record file changes or the content of alerts.");
    if (!m.online)
        items.push_back("Not readable: the device is offline, so its on-device records cannot be "
                        "read.");

    std::string h = "<div class=\"tl-lim\"><h3>What this record cannot tell you</h3><ul>";
    auto li = [&](const std::string& text, const std::string& tail = {}) {
        h += "<li>" + esc(text) + tail + "</li>";
    };
    // The list is built in the fixed order above; paused sources, capped reads and the
    // defaults note follow because they carry markup or come from other parts of the model.
    for (const auto& s : items)
        li(s);
    for (const auto& s : m.sources)
        if (is_paused(s)) {
            std::string tail;
            if (!links.retention_paused.empty())
                tail = " <a class=\"btn link sm\" href=\"" + esc(links.retention_paused) +
                       "\">Open retention-paused sources</a>";
            li((s.label.empty() ? s.source : s.label) + " is paused " +
                   paused_since(s.paused_since_ts) + "; its earlier records are kept as they were.",
               tail);
        }
    for (const auto& g : m.groups)
        for (const auto& l : g.lanes)
            if (const auto* cap = lane_cap(l))
                li(capped_read_text(l, *cap));
    li("The limits shown are the agent's defaults.");
    h += "</ul></div>";
    return h;
}

// ── moment ──────────────────────────────────────────────────────────────────────────

std::string render_timeline_moment(const TarTimelineModel& m, std::int64_t t,
                                   const TarTimelineLinks& links) {
    if (t == 0) // the route owns passing the t it set as model.moment_ts; 0 means "resolve it"
        t = tar_timeline_resolve_moment(m);
    // An offline device has no readable record, whatever regions the model carries: every lane
    // reads "Not readable", never "Nothing at this time".
    static const TarTimelineRegion kOffline = [] {
        TarTimelineRegion r;
        r.kind = TarRegionKind::not_readable;
        r.reason = TarUnreadableReason::offline;
        return r;
    }();
    const TarTimelineAdjacent adj = tar_timeline_adjacent_events(m, t);
    std::string h = "<div><div class=\"tl-det-h\"><b>" + esc(iso(t)) + "</b>" +
                    moment_nav("Previous event", adj.prev, links) +
                    moment_nav("Next event", adj.next, links) + "</div>";
    if (m.groups.empty())
        h += "<div class=\"tl-empty\">Nothing in this read.</div>";
    for (const auto& g : m.groups) {
        std::vector<StateLine> lines;
        std::vector<MomentRow> rows;
        for (const auto& l : g.lanes) {
            const TarTimelineRegion* r = m.online ? tar_timeline_region_at(l, t) : &kOffline;
            const auto items = tar_timeline_items_at(l, t);
            const bool exact = r && r->kind == TarRegionKind::exact;
            const bool rolled = r && r->kind == TarRegionKind::rolled_up;
            if (exact && !items.empty()) {
                for (const auto* it : items)
                    rows.push_back({it->label.empty() ? it->id : it->label, lane_label(l),
                                    iso(it->from_ts), it->flagged});
                continue;
            }
            if (rolled)
                for (const auto* it : items)
                    if (it->shape == TarItemShape::count || it->shape == TarItemShape::column)
                        rows.push_back({it->label.empty() ? it->id : it->label, lane_label(l),
                                        it->shape == TarItemShape::count ? num(it->count) + " events"
                                                                         : std::string(),
                                        it->flagged});
            const auto state = state_for(l, r);
            auto found = std::find_if(lines.begin(), lines.end(),
                                      [&](const StateLine& s) { return s.key == state.first; });
            if (found == lines.end()) {
                lines.push_back({state.first, state.second, {}});
                found = lines.end() - 1;
            }
            found->names.push_back(lane_label(l));
        }
        h += "<section><h3 class=\"tl-sh\">" +
             esc(g.name.empty() ? std::string("Lanes") : g.name) + "</h3>";
        for (const auto& s : lines)
            h += "<div class=\"tl-cn\"><span>" + esc(join(s.names, ", ") + ": " + s.text) +
                 "</span></div>";
        const std::size_t shown = std::min(rows.size(), kTarTimelineMomentRows);
        for (std::size_t i = 0; i < shown; ++i)
            h += std::string("<div class=\"tl-pr") + (rows[i].bad ? " bad" : "") +
                 "\"><span class=\"nm\">" + esc(rows[i].name) + "</span><span class=\"pid\">" +
                 esc(rows[i].lane) + "</span>" +
                 (rows[i].age.empty() ? "" : "<span class=\"age\">" + esc(rows[i].age) + "</span>") +
                 "</div>";
        if (rows.size() > shown)
            h += "<div class=\"tl-none\">and " + num(static_cast<std::int64_t>(rows.size() - shown)) +
                 " more</div>";
        h += "</section>";
    }
    h += "</div>";
    return h;
}

// ── selected ────────────────────────────────────────────────────────────────────────

std::string render_timeline_selected(const TarTimelineModel& m, const std::string& ref,
                                     std::int64_t t, const TarTimelineLinks& links) {
    if (t == 0) // as for the moment panel: 0 means "resolve it"
        t = tar_timeline_resolve_moment(m);
    const Found f = find_item(m, ref);
    if (!f.item)
        return "<div class=\"tl-empty\">That item is not in this read. Click a process, a count, "
               "a connection or a marker.</div>";
    const TarTimelineItem& it = *f.item;
    const std::string title = !it.title.empty() ? it.title : (!it.label.empty() ? it.label : it.id);
    std::string h = "<div class=\"tl-det-h\"><b>" + esc(title) + "</b><span class=\"pill " +
                    (it.tier == TarTier::exact ? "ok" : "warn") + "\">" +
                    esc(it.tier == TarTier::exact ? std::string("Exact") : tier_label(it.tier)) +
                    "</span>";
    if (it.flagged)
        h += "<span class=\"pill bad\">Flagged</span>";
    h += "</div><div class=\"kvl\">";
    const std::size_t facts = std::min(it.facts.size(), kMaxSelectedFacts);
    for (std::size_t i = 0; i < facts; ++i)
        h += "<div><span>" + esc(it.facts[i].first) + "</span><b>" + esc(it.facts[i].second) +
             "</b></div>";
    if (it.facts.size() > facts)
        h += "<div class=\"tl-none\">and " + num(static_cast<std::int64_t>(it.facts.size() - facts)) +
             " more</div>";
    h += "<div><span>How long it is kept</span><b>" + esc(retention_line(m, *f.lane, it)) +
         "</b></div></div>";
    if (links.selected) {
        std::string lk;
        // Only the first kMaxSelectedLinks ids are looked up (each lookup scans the model); the
        // rest are counted by id, whether or not they would resolve.
        const std::size_t links_shown = std::min(it.linked_ids.size(), kMaxSelectedLinks);
        for (std::size_t i = 0; i < links_shown; ++i) {
            const std::string& id = it.linked_ids[i];
            const Found other = find_item(m, id);
            if (!other.item)
                continue; // engine data, not a failure: an id outside this read is dropped
            const std::string& lbl = !other.item->label.empty() ? other.item->label : other.item->id;
            lk += "<a class=\"btn sm\" href=\"" + esc(links.selected(other.item->id, t)) + "\">" +
                  esc(lbl) + "</a>";
        }
        if (!lk.empty())
            h += "<div class=\"tl-lk\">" + lk + "</div>";
        if (it.linked_ids.size() > links_shown)
            h += "<div class=\"tl-none\">and " +
                 num(static_cast<std::int64_t>(it.linked_ids.size() - links_shown)) + " more</div>";
    }
    return h;
}

} // namespace yuzu::server
