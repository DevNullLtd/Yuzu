#pragma once

/// @file tar_timeline_render.hpp
/// PURE layout helpers and HTML renderers for the TAR timeline (view-model in
/// tar_timeline_view.hpp). Every function is a pure function of its arguments: no clock,
/// no store, no I/O. Every dynamic string is html_escaped; every stated time is
/// format_iso_utc (one past year 9999 is said in words); ruler labels are short forms.
/// Inline `style` attributes carry only renderer-formatted percentages, never model text.
///
/// Retention honesty: expiry statements come only from TarKeptBand::policy_s and
/// TarKeptRow::row_limit. Measured coverage (oldest_ts) draws the chart and picks the tier
/// at a moment; it never produces an expiry date or a remaining lifetime.

#include "tar_timeline_view.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

/// An item narrower than this (percent of the window) is "tiny" and may be collapsed.
inline constexpr double kTarTimelineMinBlockPct = 0.6;
/// Narrowest block drawn, so a one-second item stays visible.
inline constexpr double kTarTimelineMinWidthPct = 0.25;
/// A run of at least this many consecutive tiny items of one shape becomes one block.
inline constexpr std::size_t kTarTimelineCollapseMin = 8;
/// A lane draws at most this many blocks; the remainder is counted, not drawn.
inline constexpr std::size_t kTarTimelineMaxBlocksPerLane = 400;
/// The moment panel lists at most this many item rows per group.
inline constexpr std::size_t kTarTimelineMomentRows = 12;

/// One drawn block on a lane: an item, or a collapsed run of items.
struct TarTimelineBlock {
    std::string cls;  ///< tl-b | tl-c | tl-t | tl-k | tl-d plus modifiers (cl, cr, bad, ...)
    double left_pct = 0;
    double width_pct = 0;
    std::string label;
    std::string title;
    std::string id;           ///< empty for a collapsed block
    std::int64_t count = 0;   ///< column: 0..100 height; otherwise the item's count
    std::int64_t ts = 0;      ///< from_ts (first item's for a collapsed block)
    std::size_t items = 1;    ///< how many model items this block stands for
    TarItemShape shape = TarItemShape::bar; ///< shape of the item(s) the block draws
    bool collapsed = false;
};

struct TarTimelineLayout {
    std::vector<TarTimelineBlock> blocks;
    std::size_t overflow_count = 0;  ///< items past the per-lane block cap, not drawn
    double overflow_left_pct = 0;    ///< where the "not drawn" block starts
};

/// ts as a percentage of the window, clamped 0..100. A degenerate window yields 0.
double tar_timeline_pct(const TarTimelineModel& m, std::int64_t ts);

/// Time-to-percent layout with the shape-aware dense collapse. Items outside the window
/// are ignored. A run of >= kTarTimelineCollapseMin tiny items of the SAME shape, each
/// starting within kTarTimelineMinBlockPct of the previous end, becomes one `tl-d` block;
/// a shape change ends the run. At most kTarTimelineMaxBlocksPerLane blocks are returned.
TarTimelineLayout tar_timeline_layout_lane(const TarTimelineLane& lane, const TarTimelineModel& m);

/// The region covering t (from <= t < to; the last region is closed at its end), or
/// nullptr when no region states coverage for t. A region with to <= from is never drawn and
/// never matches. Where regions overlap it returns the one the lane draws on top: the latest
/// start, and for equal starts the later in vector order. It consults every region of the lane,
/// including any past the per-lane draw cap (kTarTimelineMaxBlocksPerLane) that the lanes
/// renderer counts but does not draw.
const TarTimelineRegion* tar_timeline_region_at(const TarTimelineLane& lane, std::int64_t t);

/// Items present at t, by shape: bar alive (from <= t < to, or open); tick at-or-before t,
/// newest first; count/column the bucket or sample with from <= t < to.
std::vector<const TarTimelineItem*> tar_timeline_items_at(const TarTimelineLane& lane,
                                                          std::int64_t t);

struct TarTimelineAdjacent {
    std::int64_t prev = 0; ///< 0 = none
    std::int64_t next = 0; ///< 0 = none
};

/// Nearest bar/tick boundary strictly below and above t, inside the window. Buckets and
/// samples are not events and are ignored.
TarTimelineAdjacent tar_timeline_adjacent_events(const TarTimelineModel& m, std::int64_t t);

/// moment_ts when inside the window, else the newest event boundary in the window (a bar's
/// start or end, a tick, a bucket's or sample's start), else window_to_ts.
std::int64_t tar_timeline_resolve_moment(const TarTimelineModel& m);

/// Host, online pill, OS and per-source chips; the two links render only when injected.
std::string render_timeline_device_bar(const TarTimelineModel& m, const TarTimelineLinks& links);

/// The "what is kept" depth chart: measured bands on a log age axis, policy as text.
std::string render_timeline_kept(const TarTimelineModel& m);

/// Banners, the time ruler (labelled once), lane rows, regions, the moment line.
std::string render_timeline_lanes(const TarTimelineModel& m);

/// "What this record cannot tell you": every bullet conditional on the model.
std::string render_timeline_limits(const TarTimelineModel& m, const TarTimelineLinks& links);

/// The moment panel at t: per-lane state, merged where identical. Pass the same t the model
/// carries as moment_ts; t == 0 is resolved with tar_timeline_resolve_moment, as the lanes and
/// the kept chart resolve theirs. An offline model reads "Not readable" for every lane.
std::string render_timeline_moment(const TarTimelineModel& m, std::int64_t t,
                                   const TarTimelineLinks& links);

/// The selected-item panel. An unknown or empty ref renders an explanation, never an empty
/// panel. t is as for render_timeline_moment (0 is resolved).
std::string render_timeline_selected(const TarTimelineModel& m, const std::string& ref,
                                     std::int64_t t, const TarTimelineLinks& links);

} // namespace yuzu::server
