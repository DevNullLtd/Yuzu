#pragma once

/// @file dex_usage_model.hpp
/// PURE fleet usage read model for the Digital Employee Experience (DEX) Apps
/// list: per application, how many devices ran it, for how long and how often
/// (a 30-day basis), and the exposure rate per hour of use. Header-only and
/// store-type-free by construction: no store header, no httplib, no JSON, no
/// clock. Every time value comes from the request (`DexUsageRequest::now_epoch`).
/// Nothing here is published by any surface yet (REST, MCP and the Apps page
/// are separate changes); the figures are aggregates and never carry an agent id.
///
/// Honesty rules (each is pinned by a test):
///  - Matching. An Apps subject matches a usage name by the ASCII-lowercased
///    exact image. A Linux device reports the kernel's `comm`, cut at 15 bytes,
///    so a Linux 15-byte usage name also matches any image that starts with it.
///    A usage name that reaches two or more Apps rows marks every one of them
///    `ambiguous_name`: those rows carry no usage figures and no rate. The rule
///    fires only when such usage rows actually exist. A name cut inside a
///    multi-byte character is altered at ingest and will not prefix-match; that
///    application reads `no_usage` (a known ceiling).
///  - One population. A device counts as reporting usage only while the server
///    received its usage state within `kDexUsageFreshSecs` (server receipt time).
///    The usage totals, the exposed events and the reporting count come from
///    the same fresh devices, so the rate's numerator and denominator share a
///    population. Stale devices are counted separately and contribute nothing.
///  - Estimated. Usage is a trailing 30-day figure. The rate scales it to the
///    window (`window_days / 30`) and says so in `kDexUsageBasis`. Window `all`
///    has no length, so its rate is withheld (`unbounded_window`); a window longer
///    than the observation retention is withheld (`window_exceeds_retention`),
///    never rescaled: rescaling both sides would stack a second estimate on the
///    first. An observation expires `retention` days after the server stored it
///    (`GuaranteedStateStore::compute_ttl_epoch`); this window is a rolling
///    `window_days` ending at the request instant, so a window no longer than
///    the retention has lost none of its events. Observations are stamped with
///    their expiry when stored, so right after an operator raises the retention
///    the store can still hold less history than the setting says (an accepted
///    ceiling, the same contract as DexAppVersionFailuresOwner).
///  - Disclosure (a floor on contributing devices). Sub-floor cells merge into
///    `other`; `other` below the floor absorbs the smallest published cell until
///    it reaches the floor; a table whose total is below the floor publishes the
///    device count only. The floor is a request field defaulting to
///    `kDexCohortFloor`.
///  - Failure is unavailable, never zero: any failed input read (group members,
///    tag values, the usage read) makes the whole model unavailable with a reason
///    token. There is no partial model.
///  - Run time is summed per process run, so "hours of use" is process-hours and
///    concurrent instances add up. Field names say run seconds, never user hours.

#include "dex_perf_model.hpp" // kDexCohortFloor, kDexDefaultCohortKey, kDexCohortExportCap
#include "dex_read_model.hpp" // DexAppsModel, DexFleet, dex_apps scope tokens
#include "dex_score_policy.hpp" // dex_score_policy_detail::ascii_lower
#include "dex_stats.hpp"        // dex_rate, DexInterval
#include "dex_window.hpp"       // dex_window_to_days, dex_iso_at

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace yuzu::server {

// ── Constants ────────────────────────────────────────────────────────────────

/// The basis of the usage figures: the agent reports a trailing 30-day total.
inline constexpr int kDexUsageBasisDays = 30;
/// The kernel cuts `comm` at 15 bytes (app_usage_parsers.hpp).
inline constexpr std::size_t kDexUsageTruncBytes = 15;
/// Named cells per table; the rest are pre-merged into `other`. Same value as
/// kDexCohortExportCap.
inline constexpr int kDexUsageCellCap = 50;
/// A cell below this many devices is flagged `small_cohort` (reliability flag).
inline constexpr std::int64_t kDexUsageSmallCohortDevices = 30;
/// 48 hours: two missed daily syncs (the agent source interval is 24 hours,
/// sync_source_app_usage.cpp). The same value as software_catalogue::kStaleWindowSecs,
/// restated here so this pure DEX header does not include the catalogue model.
inline constexpr std::int64_t kDexUsageFreshSecs = 2 * 86400;
/// Per-row clamps on agent-reported values, so one device cannot dominate a sum
/// or overflow it. 30 days of seconds times 1024 concurrent instances is
/// 2.65e9; a per-table sum over even 10^9 devices stays below 2^63 (9.2e18).
inline constexpr std::int64_t kDexUsageRowSecondsCap = 30LL * 86400 * 1024;
inline constexpr std::int64_t kDexUsageRowLaunchesCap = 1'000'000'000;

inline constexpr const char* kDexUsageBasis = "estimated_from_30_day_usage";
inline constexpr const char* kDexUsageFleetLabel = "fleet";
inline constexpr const char* kDexUsageOtherLabel = "other";
inline constexpr const char* kDexUsageUntaggedLabel = "(untagged)";

static_assert(kDexUsageCellCap == kDexCohortExportCap, "one cardinality bound for cohort tables");

// ── Request ──────────────────────────────────────────────────────────────────

enum class DexUsageSliceKind { Fleet, Platform, Group, Tag };

struct DexUsageSlice {
    DexUsageSliceKind kind{DexUsageSliceKind::Fleet};
    /// Group: the management group id. Tag: the tag key (empty = kDexDefaultCohortKey).
    std::string key;
};

struct DexUsageRequest {
    DexUsageSlice slice;
    /// The ONE request instant (epoch seconds). Required: an omitted instant
    /// would cut every event out and read as a zero-event rate.
    std::int64_t now_epoch{0};
    /// The observation store's retention in days; 0 or less = unbounded.
    int observation_retention_days{0};
    std::int64_t floor{kDexCohortFloor};
};

// ── Query / read (the cross-store owner's contract) ──────────────────────────

struct DexUsageDevice {
    std::string agent_id;
    int cell{0};
    bool is_linux{false};
};

/// One match key: `key` is compared with the usage `exe_key`. `trunc` keys
/// match only Linux devices.
struct DexUsageKey {
    int subject{0};
    std::string key;
    bool trunc{false};
};

struct DexUsageQuery {
    std::vector<DexUsageDevice> devices;
    int cell_count{0};
    std::vector<std::string> subjects; ///< raw Apps subjects, index = subject index
    std::vector<DexUsageKey> keys;
    std::string since_iso; ///< "" = no lower bound (window all)
    std::string until_iso; ///< exclusive upper bound
    std::int64_t fresh_since_epoch{0};
};

/// Aggregates only: no agent id anywhere in this type.
struct DexUsageCellRow {
    int subject{0};
    int cell{0};
    std::int64_t devices{0};
    std::int64_t exact_devices{0}; ///< of `devices`, those that matched through the exact key
    std::int64_t trunc_devices{0}; ///< of `devices`, those that matched through the trunc key
    std::int64_t launches{0};
    std::int64_t run_seconds{0};
};

struct DexUsageEventRow {
    int subject{0};
    std::int64_t crashes{0};
    std::int64_t hangs{0};
};

struct DexUsageRead {
    std::vector<DexUsageCellRow> cells;
    std::vector<DexUsageEventRow> events;
    std::int64_t reporting_devices{0}; ///< population devices whose usage state is fresh
    std::int64_t stale_devices{0};     ///< population devices with a usage state older than the cut
};

// ── Model ────────────────────────────────────────────────────────────────────

enum class DexUsageCellKind { Named, Untagged, Other };

struct DexUsageTotals {
    std::int64_t run_seconds_30d{0};
    std::int64_t launches_30d{0};
};

struct DexUsageCell {
    DexUsageCellKind kind{DexUsageCellKind::Named};
    std::string label;
    std::int64_t devices{0};
    DexUsageTotals totals;
    bool small_cohort{false};
};

struct DexExposureRate {
    DexInterval per_hour; ///< crashes + hangs per process-hour of use, at the policy's level
    double hours{0.0};    ///< the denominator: run seconds scaled to the window, in hours
    std::int64_t crashes{0};
    std::int64_t hangs{0};
    const char* basis{kDexUsageBasis};
};

enum class DexUsageState { Matched, NoUsage, AmbiguousName };

struct DexAppUsage {
    std::string subject;
    DexUsageState state{DexUsageState::NoUsage};
    std::int64_t devices{0};
    std::optional<DexUsageTotals> totals; ///< nullopt = withheld (below the floor)
    std::vector<DexUsageCell> cells;
    std::optional<DexExposureRate> rate;
    std::string rate_withheld; ///< why `rate` is absent; empty when it is present
};

struct DexAppsUsageModel {
    std::string window;
    std::string platform_scope;
    DexUsageSlice slice;
    std::int64_t population{0}; ///< devices in the platform scope online now
    std::int64_t reporting_devices{0};
    std::int64_t stale_devices{0};
    std::int64_t floor{kDexCohortFloor};
    std::vector<DexAppUsage> apps; ///< index-aligned with DexAppsModel::apps
};

// ── Matching ─────────────────────────────────────────────────────────────────

/// The match keys for the Apps subjects. Byte lengths, not characters. An image
/// of exactly 15 bytes needs no trunc key: its exact key already equals the
/// truncated name.
[[nodiscard]] inline std::vector<DexUsageKey>
dex_usage_match_plan(const std::vector<std::string>& subjects) {
    std::vector<DexUsageKey> plan;
    plan.reserve(subjects.size() * 2);
    for (std::size_t i = 0; i < subjects.size(); ++i) {
        const std::string image = dex_score_policy_detail::ascii_lower(subjects[i]);
        if (image.empty())
            continue;
        const int idx = static_cast<int>(i);
        plan.push_back({idx, image, false});
        if (image.size() > kDexUsageTruncBytes)
            plan.push_back({idx, image.substr(0, kDexUsageTruncBytes), true});
    }
    return plan;
}

/// Per subject: 1 when its usage name is shared with another subject (withhold
/// it). A subject "received rows via a key" when its exact_devices > 0 (exact
/// entry) or trunc_devices > 0 (trunc entry); when two or more distinct
/// subjects received rows via one key, all of them are ambiguous. Rows whose
/// subject index is out of range are ignored (the assembly rejects them first).
/// `std::vector<char>`, never `std::vector<bool>`.
[[nodiscard]] inline std::vector<char> dex_usage_ambiguous(const std::vector<DexUsageKey>& plan,
                                                           const std::vector<DexUsageCellRow>& rows,
                                                           std::size_t subject_count) {
    std::vector<std::int64_t> exact(subject_count, 0), trunc(subject_count, 0);
    for (const auto& r : rows) {
        if (r.subject < 0 || static_cast<std::size_t>(r.subject) >= subject_count)
            continue;
        exact[static_cast<std::size_t>(r.subject)] += r.exact_devices;
        trunc[static_cast<std::size_t>(r.subject)] += r.trunc_devices;
    }
    std::map<std::string, std::set<int>> receivers; // key -> subjects that received rows via it
    for (const auto& k : plan) {
        if (k.subject < 0 || static_cast<std::size_t>(k.subject) >= subject_count)
            continue;
        const auto s = static_cast<std::size_t>(k.subject);
        if (k.trunc ? trunc[s] > 0 : exact[s] > 0)
            receivers[k.key].insert(k.subject);
    }
    std::vector<char> out(subject_count, 0);
    for (const auto& [key, subjects] : receivers)
        if (subjects.size() >= 2)
            for (const int s : subjects)
                out[static_cast<std::size_t>(s)] = 1;
    return out;
}

// ── Cells ────────────────────────────────────────────────────────────────────

struct DexUsageCellDef {
    DexUsageCellKind kind{DexUsageCellKind::Named};
    std::string label;
};

struct DexUsageCellAssignment {
    std::vector<DexUsageCellDef> defs;
    std::vector<int> cell_of; ///< aligned with the population: exactly one cell per device
};

/// Every device gets exactly one cell, so the cells of a slice cannot overlap.
/// `population` is (agent_id, normalised os). `members` is used only by Group,
/// `values` (agent id -> tag value) only by Tag.
[[nodiscard]] inline DexUsageCellAssignment
dex_usage_assign_cells(const std::vector<std::pair<std::string, std::string>>& population,
                       const DexUsageSlice& slice, const std::unordered_set<std::string>& members,
                       const std::unordered_map<std::string, std::string>& values) {
    DexUsageCellAssignment out;
    out.cell_of.assign(population.size(), 0);
    switch (slice.kind) {
    case DexUsageSliceKind::Fleet:
        out.defs.push_back({DexUsageCellKind::Named, kDexUsageFleetLabel});
        break;
    case DexUsageSliceKind::Platform: {
        // windows, linux, macos; anything else lands in the Other cell (index 3).
        out.defs = {{DexUsageCellKind::Named, kDexAppsScopeWindows},
                    {DexUsageCellKind::Named, kDexAppsScopeLinux},
                    {DexUsageCellKind::Named, kDexAppsScopeMacos},
                    {DexUsageCellKind::Other, kDexUsageOtherLabel}};
        for (std::size_t i = 0; i < population.size(); ++i) {
            const auto& os = population[i].second;
            out.cell_of[i] = os == kDexAppsScopeWindows ? 0 : os == kDexAppsScopeLinux ? 1
                             : os == kDexAppsScopeMacos ? 2 : 3;
        }
        break;
    }
    case DexUsageSliceKind::Group:
        out.defs = {{DexUsageCellKind::Named, slice.key}, {DexUsageCellKind::Other, kDexUsageOtherLabel}};
        for (std::size_t i = 0; i < population.size(); ++i)
            out.cell_of[i] = members.contains(population[i].first) ? 0 : 1;
        break;
    case DexUsageSliceKind::Tag: {
        const auto value_of = [&](const std::string& id) -> const std::string* {
            const auto it = values.find(id);
            return it == values.end() || it->second.empty() ? nullptr : &it->second;
        };
        std::map<std::string, std::int64_t> count; // value -> devices
        for (const auto& p : population)
            if (const auto* v = value_of(p.first))
                ++count[*v];
        // The kDexUsageCellCap values with the most devices; ties by label, byte order.
        std::vector<std::pair<std::string, std::int64_t>> ranked(count.begin(), count.end());
        std::stable_sort(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
            return a.second != b.second ? a.second > b.second : a.first < b.first;
        });
        if (ranked.size() > static_cast<std::size_t>(kDexUsageCellCap))
            ranked.resize(static_cast<std::size_t>(kDexUsageCellCap));
        std::unordered_map<std::string, int> index;
        for (const auto& r : ranked) {
            index.emplace(r.first, static_cast<int>(out.defs.size()));
            out.defs.push_back({DexUsageCellKind::Named, r.first});
        }
        const int untagged = static_cast<int>(out.defs.size());
        out.defs.push_back({DexUsageCellKind::Untagged, kDexUsageUntaggedLabel});
        const int other = untagged + 1;
        out.defs.push_back({DexUsageCellKind::Other, kDexUsageOtherLabel});
        for (std::size_t i = 0; i < population.size(); ++i) {
            const auto* v = value_of(population[i].first);
            if (v == nullptr) {
                out.cell_of[i] = untagged;
                continue;
            }
            const auto it = index.find(*v);
            out.cell_of[i] = it == index.end() ? other : it->second;
        }
        break;
    }
    }
    return out;
}

// ── Disclosure ───────────────────────────────────────────────────────────────

struct DexUsageRawCell {
    DexUsageCellKind kind{DexUsageCellKind::Named};
    std::string label;
    std::int64_t devices{0};
    std::int64_t run_seconds{0};
    std::int64_t launches{0};
};

struct DexUsageDisclosed {
    std::vector<DexUsageCell> cells;
    std::int64_t devices{0}; ///< the table's contributing devices (also when withheld)
    std::optional<DexUsageTotals> totals; ///< nullopt = the table total is below the floor
};

/// The disclosure partition, in order: drop zero-device cells; a total below the
/// floor publishes the device count only; otherwise every Other-kind cell and
/// every cell below the floor moves into `other`, and while `other` is still
/// below the floor it absorbs the smallest published cell (fewest devices, ties:
/// greatest label). Published order: devices descending then label ascending,
/// Untagged after the Named cells, `other` last. Invariants: cell devices and
/// totals sum to the table's, and no published cell is below the floor.
[[nodiscard]] inline DexUsageDisclosed dex_usage_disclose(std::vector<DexUsageRawCell> raw,
                                                          std::int64_t floor) {
    DexUsageDisclosed out;
    std::erase_if(raw, [](const DexUsageRawCell& c) { return c.devices <= 0; });
    for (const auto& c : raw)
        out.devices += c.devices;
    if (raw.empty() || out.devices < floor)
        return out; // device count only

    DexUsageRawCell other{DexUsageCellKind::Other, kDexUsageOtherLabel, 0, 0, 0};
    std::vector<DexUsageRawCell> published;
    DexUsageTotals total;
    for (auto& c : raw) {
        total.run_seconds_30d += c.run_seconds;
        total.launches_30d += c.launches;
        if (c.kind == DexUsageCellKind::Other || c.devices < floor) {
            other.devices += c.devices;
            other.run_seconds += c.run_seconds;
            other.launches += c.launches;
        } else {
            published.push_back(std::move(c));
        }
    }
    while (other.devices > 0 && other.devices < floor && !published.empty()) {
        const auto smallest = std::min_element(
            published.begin(), published.end(), [](const DexUsageRawCell& a, const DexUsageRawCell& b) {
                return a.devices != b.devices ? a.devices < b.devices : a.label > b.label;
            });
        other.devices += smallest->devices;
        other.run_seconds += smallest->run_seconds;
        other.launches += smallest->launches;
        published.erase(smallest);
    }
    std::stable_sort(published.begin(), published.end(),
                     [](const DexUsageRawCell& a, const DexUsageRawCell& b) {
                         if (a.kind != b.kind)
                             return a.kind == DexUsageCellKind::Named; // Untagged after Named
                         return a.devices != b.devices ? a.devices > b.devices : a.label < b.label;
                     });
    const auto emit = [&](const DexUsageRawCell& c) {
        out.cells.push_back({c.kind, c.label, c.devices, {c.run_seconds, c.launches},
                             c.devices < kDexUsageSmallCohortDevices});
    };
    for (const auto& c : published)
        emit(c);
    if (other.devices > 0)
        emit(other);
    out.totals = total;
    return out;
}

// ── Exposure rate ────────────────────────────────────────────────────────────

struct DexExposureOutcome {
    std::optional<DexExposureRate> rate;
    std::string withheld; ///< empty when `rate` is present
};

/// Crashes + hangs per process-hour. `run_seconds` is the 30-day total, scaled
/// to the window by window_days / 30. Withheld, never rescaled, when the window
/// is unbounded or longer than the retention (see the file banner). The interval
/// level is the caller's `confidence`; dex_floored_rate is not used because it
/// fixes both the floor and the level. Reason precedence: unbounded_window,
/// window_exceeds_retention, zero_usage, no_statistic. The sibling
/// DexAppVersionFailuresOwner clamps to retention - 1 only because its window
/// is whole UTC days plus the current day; this rolling window ends at the
/// request instant and needs no such margin.
[[nodiscard]] inline DexExposureOutcome dex_usage_exposure(std::int64_t crashes, std::int64_t hangs,
                                                           std::int64_t run_seconds, int window_days,
                                                           int retention_days, double confidence) {
    if (window_days <= 0)
        return {std::nullopt, "unbounded_window"};
    if (retention_days > 0 && window_days > retention_days)
        return {std::nullopt, "window_exceeds_retention"};
    if (run_seconds <= 0)
        return {std::nullopt, "zero_usage"};
    const double hours = static_cast<double>(run_seconds) *
                         (static_cast<double>(window_days) / static_cast<double>(kDexUsageBasisDays)) /
                         3600.0;
    const auto iv = dex_rate(crashes + hangs, hours, confidence);
    if (!iv)
        return {std::nullopt, "no_statistic"};
    return {DexExposureRate{*iv, hours, crashes, hangs}, {}};
}

// ── Assembly ─────────────────────────────────────────────────────────────────

/// One DexAppUsage per Apps row, in the same order. nullopt when the read holds
/// a subject or cell index outside the Apps rows / the cell definitions: the read
/// is an injected closure, so no vector is ever indexed with an unchecked value
/// from it. Reason precedence for a withheld rate: ambiguous_name, no_usage,
/// below_floor, then dex_usage_exposure's.
[[nodiscard]] inline std::optional<DexAppsUsageModel>
dex_usage_model_from_read(const DexAppsModel& apps, const std::vector<DexUsageCellDef>& defs,
                          const std::vector<DexUsageKey>& plan, const DexUsageRead& read,
                          int window_days, int retention_days, std::int64_t floor) {
    const std::size_t n = apps.apps.size();
    for (const auto& r : read.cells)
        if (r.subject < 0 || static_cast<std::size_t>(r.subject) >= n || r.cell < 0 ||
            static_cast<std::size_t>(r.cell) >= defs.size())
            return std::nullopt;
    for (const auto& e : read.events)
        if (e.subject < 0 || static_cast<std::size_t>(e.subject) >= n)
            return std::nullopt;

    const std::vector<char> ambiguous = dex_usage_ambiguous(plan, read.cells, n);
    std::vector<std::vector<DexUsageRawCell>> raw(n);
    for (const auto& r : read.cells) {
        const auto& d = defs[static_cast<std::size_t>(r.cell)];
        raw[static_cast<std::size_t>(r.subject)].push_back(
            {d.kind, d.label, r.devices, r.run_seconds, r.launches});
    }
    std::vector<std::int64_t> crashes(n, 0), hangs(n, 0);
    for (const auto& e : read.events) {
        crashes[static_cast<std::size_t>(e.subject)] += e.crashes;
        hangs[static_cast<std::size_t>(e.subject)] += e.hangs;
    }

    DexAppsUsageModel m;
    m.window = apps.window;
    m.platform_scope = apps.platform_scope;
    m.reporting_devices = read.reporting_devices;
    m.stale_devices = read.stale_devices;
    m.floor = floor;
    m.apps.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        DexAppUsage u;
        u.subject = apps.apps[i].subject;
        if (ambiguous[i] != 0) {
            u.state = DexUsageState::AmbiguousName;
            u.rate_withheld = "ambiguous_name";
        } else if (raw[i].empty()) {
            u.state = DexUsageState::NoUsage;
            u.rate_withheld = "no_usage";
        } else {
            u.state = DexUsageState::Matched;
            auto d = dex_usage_disclose(std::move(raw[i]), floor);
            u.devices = d.devices;
            u.totals = d.totals;
            u.cells = std::move(d.cells);
            if (!u.totals) {
                u.rate_withheld = "below_floor";
            } else {
                auto x = dex_usage_exposure(crashes[i], hangs[i], u.totals->run_seconds_30d,
                                            window_days, retention_days,
                                            apps.policy.policy.interval_confidence);
                u.rate = x.rate;
                u.rate_withheld = std::move(x.withheld);
            }
        }
        m.apps.push_back(std::move(u));
    }
    return m;
}

// ── Builder ──────────────────────────────────────────────────────────────────

/// The three injected reads. An empty closure is a failed read.
struct DexUsageSources {
    std::function<std::optional<DexUsageRead>(const DexUsageQuery&)> read;
    std::function<std::optional<std::vector<std::string>>(const std::string& group_id)> group_members;
    std::function<std::optional<std::unordered_map<std::string, std::string>>(const std::string& key)>
        tag_values;
};

/// Refusal tokens: invalid_request, apps_degraded, no_population, invalid_slice,
/// group_unavailable, tag_unavailable, usage_unavailable. Read-only and
/// stateless: nothing to recover after a crash, a repeat request is idempotent,
/// and one failed input fails the whole model. The membership reads complete
/// before the usage read starts, so no lease is held across another.
[[nodiscard]] inline std::expected<DexAppsUsageModel, std::string>
build_dex_apps_usage_model(const DexAppsModel& apps, const DexFleet& fleet, const DexUsageRequest& req,
                           const DexUsageSources& src) {
    using std::unexpected;
    if (req.now_epoch <= 0)
        return unexpected(std::string("invalid_request"));
    if (apps.degraded)
        return unexpected(std::string("apps_degraded"));
    if (!apps.population)
        return unexpected(std::string("no_population"));
    if (req.slice.kind == DexUsageSliceKind::Group && req.slice.key.empty())
        return unexpected(std::string("invalid_slice"));

    // The Apps read's own population: the platform scope's online devices.
    std::vector<std::pair<std::string, std::string>> population;
    for (const auto& [id, os] : fleet.connected_agents)
        if (apps.platform_scope == kDexAppsScopeAll || os == apps.platform_scope)
            population.emplace_back(id, os);

    DexUsageSlice slice = req.slice;
    std::unordered_set<std::string> members;
    std::unordered_map<std::string, std::string> values;
    if (slice.kind == DexUsageSliceKind::Group) {
        auto got = src.group_members ? src.group_members(slice.key) : std::nullopt;
        if (!got)
            return unexpected(std::string("group_unavailable"));
        members.insert(got->begin(), got->end());
    } else if (slice.kind == DexUsageSliceKind::Tag) {
        if (slice.key.empty())
            slice.key = kDexDefaultCohortKey;
        auto got = src.tag_values ? src.tag_values(slice.key) : std::nullopt;
        if (!got)
            return unexpected(std::string("tag_unavailable"));
        values = std::move(*got);
    }

    const DexUsageCellAssignment cells = dex_usage_assign_cells(population, slice, members, values);

    DexUsageQuery q;
    q.devices.reserve(population.size());
    for (std::size_t i = 0; i < population.size(); ++i)
        q.devices.push_back({population[i].first, cells.cell_of[i], population[i].second == kDexAppsScopeLinux});
    q.cell_count = static_cast<int>(cells.defs.size());
    q.subjects.reserve(apps.apps.size());
    for (const auto& a : apps.apps)
        q.subjects.push_back(a.subject);
    q.keys = dex_usage_match_plan(q.subjects);
    const int days = dex_window_to_days(apps.window);
    // The same arithmetic as dex_iso_since, from the one request instant.
    q.since_iso = days > 0 ? dex_iso_at(req.now_epoch - static_cast<std::int64_t>(days) * 86400)
                           : std::string{};
    q.until_iso = dex_iso_at(req.now_epoch);
    q.fresh_since_epoch = req.now_epoch - kDexUsageFreshSecs;

    // An Apps model with no rows is not an early return: the read still runs with an
    // empty key list so the coverage counts are real.
    const auto read = src.read ? src.read(q) : std::nullopt;
    if (!read)
        return unexpected(std::string("usage_unavailable"));
    auto model = dex_usage_model_from_read(apps, cells.defs, q.keys, *read, days,
                                           req.observation_retention_days, req.floor);
    if (!model)
        return unexpected(std::string("usage_unavailable"));
    model->slice = slice;
    model->population = static_cast<std::int64_t>(population.size());
    return std::move(*model);
}

} // namespace yuzu::server
