#pragma once

/// @file tar_timeline_view.hpp
/// View-model for the TAR timeline: plain value types the engine fills and the pure
/// renderers in tar_timeline_render.hpp read. No behaviour lives here.
///
/// Engine contract (what a filler of this model must honour):
///  - Every time is epoch seconds, UTC.
///  - Each lane's `regions` are clipped to [window_from_ts, window_to_ts] and must cover
///    that window. A stretch no region covers renders "Coverage not stated"; the renderer
///    never assumes a stretch is exact (empty is not exact).
///  - Items outside the window are ignored by layout.
///  - `moment_ts == 0` means "the newest event in the read".
///  - TarKeptBand::oldest_ts is MEASURED coverage: the oldest row or bucket the engine
///    observed for that tier on this device (0 = none observed). It is an absolute
///    boundary, never a duration, and never a projected reach.
///  - TarKeptBand::policy_s is the tier's CONFIGURED retention duration from the registry
///    defaults (0 = row-limited for the exact tier, otherwise not stated). The renderer
///    states the policy as text and never derives an expiry or a remaining lifetime from
///    oldest_ts.
///  - process_capture_method is copied from the device's `tar status` key of the same
///    name (etw | endpoint_security | polling | empty = unknown). It is the LIVE path at
///    read time and the only source of the capture claim; the renderer never infers it
///    from `os`.
///
/// There is deliberately no fleet, story, server-lane or incident field.
///
/// Design to repo class map (the artboard's three prefixes all became `.tl-`):
///   .tm-top -> .tl-top   .tm-host -> .tl-host  .tm-ctl -> .tl-ctl  .tm-leg -> .tl-leg
///   .tm-b   -> .tl-b     .tm-c    -> .tl-c     .tm-d   -> .tl-d    .tm-k   -> .tl-k
///   .tm-t   -> .tl-t     .tl-gap  -> .tl-rg    .tm-sh  -> .tl-sh   .tm-pr  -> .tl-pr
///   .tm-cn  -> .tl-cn    .tm-lim  -> .tl-lim   .tm-det-h -> .tl-det-h  .tm-empty -> .tl-empty
///   .dp     -> .tl-kp    .dp-row  -> .tl-kr    .dp-ax  -> .tl-kax  .dp-seg -> .tl-ks
///   .dp-mk  -> .tl-kmk   .dp-leg  -> .tl-kleg  .dp-note -> .tl-knote

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::server {

/// Retention tier of a record, newest-detail first.
enum class TarTier { exact, hourly, daily, monthly };

/// What the engine can say about one stretch of one lane.
enum class TarRegionKind { exact, rolled_up, pruned, paused, not_readable, capped };

/// Why a stretch could not be read (kind == not_readable).
enum class TarUnreadableReason { offline, read_failed, agent_too_old };

/// How an item is drawn: a span, a state change, a bucket count, or a sample column.
enum class TarItemShape { bar, tick, count, column };

/// A stretch of a lane's time axis with one coverage state.
struct TarTimelineRegion {
    std::int64_t from_ts = 0;
    std::int64_t to_ts = 0;
    TarRegionKind kind = TarRegionKind::exact;
    TarTier tier = TarTier::exact;                         ///< rolled_up: which roll-up
    TarUnreadableReason reason = TarUnreadableReason::offline; ///< not_readable only
    std::int64_t paused_since_ts = 0;                      ///< paused only
    std::int64_t cap_rows = 0;                             ///< capped only: the row limit hit
    std::int64_t coverage_from_ts = 0;                     ///< capped only: oldest time shown
};

/// One drawable thing on a lane.
struct TarTimelineItem {
    std::string id;
    TarItemShape shape = TarItemShape::bar;
    std::int64_t from_ts = 0;
    /// bar: 0 = still open at window end. count/column: the bucket or sample end.
    std::int64_t to_ts = 0;
    std::string label;
    std::string title;
    /// count: events in the bucket. column: 0..100.
    std::int64_t count = 0;
    TarTier tier = TarTier::exact;
    bool flagged = false;
    /// Engine-supplied rows for the selected panel.
    std::vector<std::pair<std::string, std::string>> facts;
    std::vector<std::string> linked_ids;
};

/// One row of the timeline.
struct TarTimelineLane {
    std::string id;
    std::string source; ///< process | tcp | dns | arp | service | user | perf
    std::string name;
    std::string sub;
    int depth = 0;
    bool flagged = false;
    std::vector<TarTimelineItem> items;
    std::vector<TarTimelineRegion> regions;
};

struct TarTimelineGroup {
    std::string name;
    std::vector<TarTimelineLane> lanes;
};

/// Whether a source records on this device.
struct TarSourceState {
    std::string source;
    std::string label;
    bool enabled = true;
    std::int64_t paused_since_ts = 0; ///< 0 = not paused
};

/// Measured coverage and configured policy for one tier of one source.
struct TarKeptBand {
    TarTier tier = TarTier::exact;
    std::int64_t oldest_ts = 0; ///< measured, absolute; 0 = none observed
    std::int64_t policy_s = 0;  ///< configured duration; 0 = row-limited (exact) or not stated
};

/// One row of the "what is kept" chart.
struct TarKeptRow {
    std::string source;
    std::string label;
    std::int64_t row_limit = 0; ///< exact tier row limit; 0 = time-limited
    std::vector<TarKeptBand> bands;
    std::int64_t paused_since_ts = 0;
};

struct TarTimelineModel {
    std::string agent_id;
    std::string hostname;
    std::string os; ///< normalized with normalize_tar_os
    bool online = false;
    std::int64_t read_ts = 0;
    std::int64_t window_from_ts = 0;
    std::int64_t window_to_ts = 0;
    std::int64_t moment_ts = 0; ///< 0 = newest event in the read
    std::optional<int> poll_interval_s;
    std::string process_capture_method;
    std::vector<TarSourceState> sources;
    std::vector<TarKeptRow> kept;
    std::vector<TarTimelineGroup> groups;
};

/// Every URL the renderers emit is injected; none is pinned here.
struct TarTimelineLinks {
    std::function<std::string(std::int64_t)> moment;                       ///< moment(ts)
    std::function<std::string(const std::string&, std::int64_t)> selected; ///< selected(id, ts)
    std::string device;
    std::string choose_device;
    std::string retention_paused;
    std::string retention_settings;
};

} // namespace yuzu::server
