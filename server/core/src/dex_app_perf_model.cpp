#include "dex_app_perf_model.hpp"

#include "dex_perf_model.hpp" // kDexCohortFloor — the ONE cohort floor constant

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include <string_view>
#include <utility>

namespace yuzu::server {

using json = nlohmann::json;

bool app_perf_param_valid(std::string_view s) {
    if (s.size() > kAppPerfParamCap)
        return false;
    for (const unsigned char c : s)
        if (c < 0x20) // C0 control incl. NUL (NUL truncates a bound libpq text param)
            return false;
    return true;
}

std::optional<HistPctile> percentile_from_hist(const std::vector<std::int64_t>& hist,
                                               const std::vector<double>& boundaries, double p) {
    // Scheme guard: N boundaries → N+1 buckets. A mismatch is a corrupt or
    // wrong-scheme row — withhold rather than read counts under wrong cut points.
    if (hist.size() != boundaries.size() + 1)
        return std::nullopt;

    std::int64_t total = 0;
    for (const std::int64_t c : hist)
        total += (c > 0 ? c : 0); // a negative count is corruption; ignore it
    if (total <= 0)
        return std::nullopt; // empty population — absent, never a fabricated 0

    p = std::clamp(p, 0.0, 1.0);
    // Nearest-rank DIRECTION, matching detail::nearest_rank: the 1-based rank
    // r = ceil(p·total), floored at 1 and capped at total. The percentile is the
    // value of the element at that rank; we return the lower edge of the bucket
    // that element lands in (bucket-resolution approximation).
    auto r = static_cast<std::int64_t>(std::ceil(p * static_cast<double>(total)));
    r = std::clamp<std::int64_t>(r, 1, total);

    const std::size_t n = boundaries.size(); // top (open) bucket index == n
    std::int64_t cum = 0;
    for (std::size_t b = 0; b < hist.size(); ++b) {
        const std::int64_t c = hist[b] > 0 ? hist[b] : 0;
        cum += c;
        if (cum >= r) {
            HistPctile out;
            // Lower edge: bucket 0 → metric floor 0; bucket b → boundaries[b-1];
            // top open bucket n → boundaries[n-1] as a FLOOR.
            if (b == 0)
                out.value = 0.0;
            else
                out.value = boundaries[b - 1];
            out.lower_bound = (b == n); // open top bucket → "≥ value"
            return out;
        }
    }
    // Unreachable when total > 0 (cum reaches total ≥ r), but stay defensive.
    return std::nullopt;
}

namespace {

// WS boundaries widened to double once (≤ 8 GiB is exact in double). Shared by
// every trend point so we don't rebuild the vector per row.
const std::vector<double>& ws_boundaries_d() {
    static const std::vector<double> kWs = [] {
        std::vector<double> v;
        for (const std::int64_t b : app_perf_ws_buckets())
            v.push_back(static_cast<double>(b));
        return v;
    }();
    return kWs;
}

// PURE: reduce B2 rows to trend points WITHOUT the floor — the exact mean +
// percentile + hist_version gate, one row in → one point out. The cohort floor is
// applied on top by the public fleet/group entry points so they share one
// histogram reading and one suppression rule.
std::vector<AppPerfTrendPoint> build_trend(const std::vector<AppPerfFleetRow>& rows) {
    std::vector<AppPerfTrendPoint> out;
    out.reserve(rows.size());
    for (const AppPerfFleetRow& row : rows) {
        AppPerfTrendPoint pt;
        pt.version = row.version;
        pt.day = row.day;
        pt.device_count = row.device_count;
        pt.cpu_max = row.cpu_max;
        pt.ws_max = row.ws_max;
        if (row.device_count > 0) {
            pt.cpu_mean = row.cpu_sum / static_cast<double>(row.device_count);
            // Integer mean of bytes — rounded, never a divide-by-zero.
            pt.ws_mean = static_cast<std::int64_t>(
                std::llround(static_cast<double>(row.ws_sum) /
                             static_cast<double>(row.device_count)));
        }
        // Withhold percentiles for a row built under a different scheme — never
        // reinterpret its counts under the current buckets.
        if (row.hist_version == kAppPerfHistVersion) {
            pt.cpu_p50 = percentile_from_hist(row.cpu_hist, app_perf_cpu_buckets(), 0.50);
            pt.cpu_p95 = percentile_from_hist(row.cpu_hist, app_perf_cpu_buckets(), 0.95);
            pt.ws_p50 = percentile_from_hist(row.ws_hist, ws_boundaries_d(), 0.50);
            pt.ws_p95 = percentile_from_hist(row.ws_hist, ws_boundaries_d(), 0.95);
        } else {
            pt.hist_stale = true;
        }
        out.push_back(std::move(pt));
    }
    return out;
}

// Sub-floor suppression: a (version, day) point covering fewer than `floor`
// devices is de-facto individual behaviour (singling-out — works-council / GDPR
// needs no name), so its stats are withheld and only the honest device_count
// survives. Applied to BOTH the fleet and group paths (a niche app on N<floor
// devices is just as identifying fleet-wide as inside a named group).
void apply_cohort_floor(std::vector<AppPerfTrendPoint>& points, std::int64_t floor) {
    for (AppPerfTrendPoint& pt : points) {
        if (pt.device_count < floor) {
            pt.suppressed = true;
            pt.cpu_mean = 0.0;
            pt.cpu_max = 0.0;
            pt.ws_mean = 0;
            pt.ws_max = 0;
            pt.cpu_p50.reset();
            pt.cpu_p95.reset();
            pt.ws_p50.reset();
            pt.ws_p95.reset();
        }
    }
}

} // namespace

std::vector<AppPerfTrendPoint> app_perf_fleet_trend(const std::vector<AppPerfFleetRow>& rows) {
    // The fleet trend floors at kDexCohortFloor too: a sub-floor (version, day) point
    // singles out one operator's exact CPU/mem even without an agent_id, so it is
    // withheld (count only) — the same protection the named-group path applies, NOT
    // a fleet-only exemption (governance compliance-HIGH / sec-MED).
    std::vector<AppPerfTrendPoint> points = build_trend(rows);
    apply_cohort_floor(points, kDexCohortFloor);
    return points;
}

std::vector<AppPerfVersionSummary>
app_perf_version_summaries(const std::vector<AppPerfTrendPoint>& points) {
    std::vector<AppPerfVersionSummary> out;
    // Per-version (day, cpu_mean) pairs, aligned with `out` by index — collected
    // here so the sparkline series can be sorted chronologically regardless of input
    // order. Index access (not a held pointer-into-vector) sidesteps any
    // use-after-realloc on push_back.
    std::vector<std::vector<std::pair<std::int64_t, double>>> series;
    // version -> index into `out`. A std::map (tree, O(log n) per lookup → O(n log n)
    // total) replaces the prior linear scan so an app carrying many agent-supplied
    // version strings cannot drive this to O(versions²) (UP-1, sibling of
    // app_perf_device_summaries). Ordered, not hashed: the keys are agent-controlled,
    // so a tree is immune to the hash-flooding an unordered_map would suffer. `out`
    // is still built in first-seen order (push_back on miss), the map only indexes.
    std::map<std::string, std::size_t> version_index;
    for (const AppPerfTrendPoint& pt : points) {
        auto it = version_index.find(pt.version);
        std::size_t idx;
        if (it != version_index.end()) {
            idx = it->second;
        } else {
            idx = out.size();
            AppPerfVersionSummary fresh;
            fresh.version = pt.version;
            out.push_back(std::move(fresh));
            series.emplace_back();
            version_index.emplace(pt.version, idx);
        }
        AppPerfVersionSummary& s = out[idx];
        ++s.day_count;
        if (!pt.suppressed)
            series[idx].emplace_back(pt.day, pt.cpu_mean); // real means only; cleared days skipped
        // Headline = the latest day seen for this version (`>=` makes it order-robust
        // and keeps a single-day version honest).
        if (pt.day >= s.latest_day) {
            s.latest_day = pt.day;
            s.device_count = pt.device_count;
            s.suppressed = pt.suppressed;
            s.hist_stale = pt.hist_stale;
            s.cpu_mean = pt.cpu_mean;
            s.cpu_max = pt.cpu_max;
            s.cpu_p95 = pt.cpu_p95;
            s.ws_mean = pt.ws_mean;
        }
    }
    // Sort each version's series by day, then project to the chronological sparkline.
    for (std::size_t k = 0; k < out.size(); ++k) {
        auto& pairs = series[k];
        std::sort(pairs.begin(), pairs.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        out[k].cpu_series.reserve(pairs.size());
        for (const auto& [day, mean] : pairs)
            out[k].cpu_series.push_back(mean);
    }
    return out;
}

std::vector<AppPerfTrendPoint> app_perf_group_trend(const std::vector<AppPerfFleetRow>& rows,
                                                    std::int64_t floor) {
    // Same build + suppression as the fleet path; the group passes its own floor
    // (kDexCohortFloor from the REST/MCP/dashboard callers). Shares one histogram
    // reading + one floor rule with the fleet path so the surfaces cannot disagree.
    std::vector<AppPerfTrendPoint> points = build_trend(rows);
    apply_cohort_floor(points, floor);
    return points;
}

namespace {

// Per-(app, version) accumulator over a single device's daily rows. The parallel
// `series` vector (index-aligned with the accumulator vector) collects (day,
// cpu_avg) so the sparkline is sorted chronologically regardless of input order —
// the same index-not-pointer discipline as app_perf_version_summaries.
struct DeviceAcc {
    std::string app;
    std::string version;
    std::int64_t latest_day{0};
    std::int64_t day_count{0};
    std::int64_t instances_max{0};
    double cpu_max{0.0};
    std::int64_t ws_max{0};
    double cpu_weighted_sum{0.0}; ///< Σ cpu_avg·samples
    double ws_weighted_sum{0.0};  ///< Σ ws_avg·samples
    std::int64_t sample_sum{0};   ///< Σ samples (the weight denominator)
    double cpu_plain_sum{0.0};    ///< Σ cpu_avg (zero-weight fallback numerator)
    double ws_plain_sum{0.0};     ///< Σ ws_avg (zero-weight fallback numerator)
    std::int64_t row_count{0};    ///< days seen (fallback denominator)
};

// Defensive cap on the per-version sparkline length. With the store's day-bound
// (apply_daily drops rows outside the retention window) a legitimate series is
// ≤ retention (~31 days), so this never truncates real data — it is belt-and-
// suspenders against a degenerate/oversized input reaching this pure fn (e.g. a
// future caller, or if the day-bound were ever weakened), keeping spark() from
// emitting a multi-MB SVG polyline (UP-2). We keep the MOST RECENT points.
constexpr std::size_t kMaxSeriesPoints = 400;

} // namespace

std::vector<AppPerfDeviceApp> app_perf_device_summaries(const std::vector<AppPerfDailyRow>& rows) {
    std::vector<DeviceAcc> accs;
    std::vector<std::vector<std::pair<std::int64_t, double>>> series;
    // (app, version) -> index into accs. A std::map (tree, O(log n) per lookup →
    // O(n log n) total) replaces the prior linear scan: the agent controls these
    // keys and can push up to kQueryRowCap (1e5) distinct ones, so the old
    // back()+scan was O(distinct²) ≈ 1e10 compares on one web thread = a dashboard
    // DoS (UP-1). Ordered, not hashed — a tree is immune to the hash-flooding an
    // unordered_map would suffer on adversarial keys.
    std::map<std::pair<std::string, std::string>, std::size_t> acc_index;

    for (const AppPerfDailyRow& r : rows) {
        const auto it = acc_index.find({r.app_name, r.version});
        std::size_t idx;
        if (it != acc_index.end()) {
            idx = it->second;
        } else {
            idx = accs.size();
            DeviceAcc fresh;
            fresh.app = r.app_name;
            fresh.version = r.version;
            accs.push_back(std::move(fresh));
            series.emplace_back();
            acc_index.emplace(std::pair{r.app_name, r.version}, idx);
        }
        DeviceAcc& a = accs[idx];
        ++a.day_count;
        ++a.row_count;
        a.latest_day = (std::max)(a.latest_day, r.day);
        a.instances_max = (std::max)(a.instances_max, r.instances_max);
        a.cpu_max = (std::max)(a.cpu_max, r.cpu_max);
        a.ws_max = (std::max)(a.ws_max, r.ws_max_bytes);
        const std::int64_t w = r.samples > 0 ? r.samples : 0;
        a.cpu_weighted_sum += r.cpu_avg * static_cast<double>(w);
        a.ws_weighted_sum += static_cast<double>(r.ws_avg_bytes) * static_cast<double>(w);
        a.sample_sum += w;
        a.cpu_plain_sum += r.cpu_avg;
        a.ws_plain_sum += static_cast<double>(r.ws_avg_bytes);
        series[idx].emplace_back(r.day, r.cpu_avg);
    }

    // Reduce each accumulator to a version summary, group under its app (first-seen
    // app order preserved here; the final sort re-orders by resource).
    std::vector<AppPerfDeviceApp> apps;
    std::map<std::string, std::size_t> app_index; // app_name -> index into apps (UP-1)
    for (std::size_t k = 0; k < accs.size(); ++k) {
        const DeviceAcc& a = accs[k];
        AppPerfDeviceVersion v;
        v.version = a.version;
        v.latest_day = a.latest_day;
        v.day_count = a.day_count;
        v.instances_max = a.instances_max;
        v.cpu_max = a.cpu_max;
        v.ws_max = a.ws_max;
        if (a.sample_sum > 0) {
            v.cpu_avg = a.cpu_weighted_sum / static_cast<double>(a.sample_sum);
            v.ws_avg = static_cast<std::int64_t>(
                std::llround(a.ws_weighted_sum / static_cast<double>(a.sample_sum)));
        } else if (a.row_count > 0) {
            // Zero total samples (malformed rows) — unweighted mean, never a divide.
            v.cpu_avg = a.cpu_plain_sum / static_cast<double>(a.row_count);
            v.ws_avg = static_cast<std::int64_t>(
                std::llround(a.ws_plain_sum / static_cast<double>(a.row_count)));
        }
        auto& pairs = series[k]; // sort in place — series[k] is dead afterwards
        std::sort(pairs.begin(), pairs.end(),
                  [](const auto& x, const auto& y) { return x.first < y.first; });
        // Keep the most-recent kMaxSeriesPoints (UP-2 belt: bound the sparkline).
        const std::size_t start = pairs.size() > kMaxSeriesPoints ? pairs.size() - kMaxSeriesPoints : 0;
        v.cpu_series.reserve(pairs.size() - start);
        for (std::size_t i = start; i < pairs.size(); ++i)
            v.cpu_series.push_back(pairs[i].second);

        const auto ait = app_index.find(a.app);
        std::size_t ai;
        if (ait != app_index.end()) {
            ai = ait->second;
        } else {
            ai = apps.size();
            AppPerfDeviceApp na;
            na.app_name = a.app;
            apps.push_back(std::move(na));
            app_index.emplace(a.app, ai);
        }
        AppPerfDeviceApp& app = apps[ai];
        app.latest_day = (std::max)(app.latest_day, v.latest_day);
        app.peak_cpu_avg = (std::max)(app.peak_cpu_avg, v.cpu_avg);
        app.versions.push_back(std::move(v));
    }

    for (auto& app : apps)
        std::sort(app.versions.begin(), app.versions.end(),
                  [](const AppPerfDeviceVersion& x, const AppPerfDeviceVersion& y) {
                      if (x.latest_day != y.latest_day)
                          return x.latest_day > y.latest_day; // newest day first
                      return x.version < y.version;
                  });
    std::sort(apps.begin(), apps.end(),
              [](const AppPerfDeviceApp& x, const AppPerfDeviceApp& y) {
                  if (x.peak_cpu_avg != y.peak_cpu_avg)
                      return x.peak_cpu_avg > y.peak_cpu_avg; // resource-significant first
                  return x.app_name < y.app_name;
              });
    return apps;
}

// ── Per-version crash and hang join ──────────────────────────────────────────

namespace {

// Next dot-separated group of a canonical version as a number. Canonical groups
// are digits only; a stray character ends the group's value rather than
// throwing, and the value saturates so an absurd group cannot overflow.
std::int64_t next_group(std::string_view& rest) {
    const auto dot = rest.find('.');
    const std::string_view grp = rest.substr(0, dot);
    rest = dot == std::string_view::npos ? std::string_view{} : rest.substr(dot + 1);
    std::int64_t v = 0;
    for (const char c : grp) {
        if (c < '0' || c > '9')
            break;
        if (v > ((std::numeric_limits<std::int64_t>::max)() - 9) / 10)
            return (std::numeric_limits<std::int64_t>::max)();
        v = v * 10 + (c - '0');
    }
    return v;
}

json interval_json(const DexInterval& i, bool ratio) {
    const bool inf_upper = !std::isfinite(i.upper);
    json o{{"lower", i.lower}, {"reliable", i.reliable}};
    o["estimate"] = std::isfinite(i.estimate) ? json(i.estimate) : json(nullptr);
    o["upper"] = inf_upper ? json(nullptr) : json(i.upper);
    if (ratio)
        o["unbounded"] = inf_upper;
    return o;
}

json opt_i64(const std::optional<std::int64_t>& v) {
    return v ? json(*v) : json(nullptr);
}

} // namespace

bool app_perf_canon_version_less(std::string_view a, std::string_view b) {
    if (a.empty() || b.empty())
        return a.empty() && !b.empty();
    while (!a.empty() || !b.empty()) {
        const std::int64_t ga = next_group(a);
        const std::int64_t gb = next_group(b);
        if (ga != gb)
            return ga < gb;
    }
    return false;
}

AppPerfNewestVersions app_perf_newest_versions(const std::vector<AppPerfTrendPoint>& points) {
    AppPerfNewestVersions sel;
    auto& versions = sel.versions;
    versions.reserve(points.size());
    for (const auto& p : points)
        versions.push_back(p.version);
    // The final tie-break is byte order, so comparator-equal means byte-equal and
    // duplicates are adjacent after the sort.
    std::sort(versions.begin(), versions.end(), [](const std::string& x, const std::string& y) {
        if (app_perf_canon_version_less(y, x))
            return true;
        if (app_perf_canon_version_less(x, y))
            return false;
        return x < y;
    });
    versions.erase(std::unique(versions.begin(), versions.end()), versions.end());
    sel.truncated = versions.size() > kAppPerfVersionJoinCap;
    if (sel.truncated)
        versions.resize(kAppPerfVersionJoinCap);
    return sel;
}

AppPerfFleetReport app_perf_version_failure_join(std::vector<AppPerfTrendPoint> points,
                                                 const std::vector<AppPerfVersionFailureRow>& failures,
                                                 int failure_window_days) {
    AppPerfFleetReport rep;
    rep.failure_window_days = failure_window_days;

    auto summaries = app_perf_version_summaries(points);
    // Rows are emitted in the shared selection's order (newest first, capped).
    const auto sel = app_perf_newest_versions(points);
    const auto& keep = sel.versions;
    rep.versions_truncated = sel.truncated;
    std::map<std::string, std::size_t> summary_index; // tree: agent-controlled keys
    for (std::size_t i = 0; i < summaries.size(); ++i)
        summary_index.emplace(summaries[i].version, i);
    {
        std::vector<AppPerfVersionSummary> ordered;
        ordered.reserve(keep.size());
        for (const auto& v : keep)
            ordered.push_back(std::move(summaries[summary_index.at(v)]));
        summaries = std::move(ordered);
    }
    rep.points = std::move(points);

    // Agent-controlled keys, so a tree rather than a hash map (as above).
    std::map<std::string, const AppPerfVersionFailureRow*> by_version;
    for (const auto& f : failures)
        by_version.emplace(f.version, &f);

    // Exposed events per row, kept beside the rows for the ratio's second arm.
    std::vector<std::int64_t> exposed_events(summaries.size(), 0);
    rep.versions.reserve(summaries.size());
    for (std::size_t i = 0; i < summaries.size(); ++i) {
        AppPerfVersionRow row;
        row.perf = std::move(summaries[i]);
        AppPerfVersionFailureRow f;
        if (const auto it = by_version.find(row.perf.version); it != by_version.end())
            f = *it->second;

        // No device floor on this join (maintainer ruling 2026-10-14): every count
        // is published at any device count.
        row.affected_devices = f.affected_devices;
        row.crashes = f.crashes;
        row.hangs = f.hangs;
        row.exposure_devices = f.exposure_devices;
        if (f.exposure_devices) {
            exposed_events[i] = f.exposed_crashes + f.exposed_hangs;
            row.exposed_crashes = f.exposed_crashes;
            row.exposed_hangs = f.exposed_hangs;
            // A zero or negative exposure is a refusal (no divide by zero, no
            // healthy zero), not a failure; a corrupt event count is a failure.
            if (*f.exposure_devices > 0) {
                row.failure_rate =
                    dex_rate(exposed_events[i], static_cast<double>(*f.exposure_devices));
                if (!row.failure_rate)
                    ++rep.stat_failures;
            }
        }
        rep.versions.push_back(std::move(row));
    }

    // Each known version is compared with the next older known version; the
    // unknown ("") bucket sorts last and takes no part in the chain.
    for (std::size_t i = 0; i + 1 < rep.versions.size(); ++i) {
        AppPerfVersionRow& cur = rep.versions[i];
        const AppPerfVersionRow& prev = rep.versions[i + 1];
        if (cur.perf.version.empty() || prev.perf.version.empty())
            continue;
        cur.previous_version = prev.perf.version;
        if (!cur.exposure_devices || !prev.exposure_devices || *cur.exposure_devices <= 0 ||
            *prev.exposure_devices <= 0)
            continue;
        // The exposure is a device count the join does not floor: the minimum
        // exposure is 1, not the default device floor.
        cur.failure_rate_ratio =
            dex_rate_ratio(exposed_events[i], static_cast<double>(*cur.exposure_devices),
                           exposed_events[i + 1], static_cast<double>(*prev.exposure_devices), 1.0);
        // Both arms zero-event, or an arm past the ratio's accuracy limit, are
        // documented refusals; any other missing ratio is a computation failure.
        const bool refusal = (exposed_events[i] == 0 && exposed_events[i + 1] == 0) ||
                             exposed_events[i] > kDexRateRatioMaxEvents ||
                             exposed_events[i + 1] > kDexRateRatioMaxEvents;
        if (!cur.failure_rate_ratio && !refusal)
            ++rep.stat_failures;
    }
    return rep;
}

std::string dex_app_perf_versions_json(const AppPerfFleetReport& report) {
    json arr = json::array();
    for (const AppPerfVersionRow& r : report.versions) {
        json o;
        o["version"] = r.perf.version;
        o["latest_day"] = r.perf.latest_day;
        o["day_count"] = r.perf.day_count;
        o["device_count"] = r.perf.device_count;
        o["suppressed"] = r.perf.suppressed;
        o["affected_devices"] = r.affected_devices;
        o["crashes"] = r.crashes;
        o["hangs"] = r.hangs;
        o["exposure_devices"] = opt_i64(r.exposure_devices);
        o["exposed_crashes"] = opt_i64(r.exposed_crashes);
        o["exposed_hangs"] = opt_i64(r.exposed_hangs);
        o["failure_rate"] = r.failure_rate ? interval_json(*r.failure_rate, false) : json(nullptr);
        o["previous_version"] = r.previous_version.empty() ? json(nullptr) : json(r.previous_version);
        o["failure_rate_ratio"] =
            r.failure_rate_ratio ? interval_json(*r.failure_rate_ratio, true) : json(nullptr);
        arr.push_back(std::move(o));
    }
    return arr.dump();
}

// ── MCP-only gap #2: per-device app-perf drill serializer (ADR-0031 WS-A4
//    DexPerfApi seam, PR #4582 review — relocated here from the DEX signals
//    seam's dex_read_builders.hpp/.cpp, which only ever parked it pending this
//    seam's arrival) ────────────────────────────────────────────────────────

std::string dex_device_app_perf_json(const std::string& agent_id, const std::string& app_filter,
                                     const std::vector<AppPerfDailyRow>& rows,
                                     bool audit_persisted) {
    json arr = json::array();
    for (const auto& r : rows) {
        if (!app_filter.empty() && r.app_name != app_filter)
            continue;
        arr.push_back({{"app_name", r.app_name},
                       {"version", r.version},
                       {"day", r.day},
                       {"samples", r.samples},
                       {"instances_max", r.instances_max},
                       {"cpu_avg", r.cpu_avg},
                       {"cpu_max", r.cpu_max},
                       {"ws_avg_bytes", r.ws_avg_bytes},
                       {"ws_max_bytes", r.ws_max_bytes}});
    }
    json out{{"agent_id", agent_id}, {"app", app_filter}};
    out["rows"] = std::move(arr);
    if (!audit_persisted)
        out["audit_persisted"] = false;
    return out.dump();
}

} // namespace yuzu::server
