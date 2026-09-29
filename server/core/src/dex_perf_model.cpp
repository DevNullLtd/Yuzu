#include "dex_perf_model.hpp"

#include "dex_perf_rules.hpp"

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

using detail::nearest_rank;

/// Build a DexPerfStat from raw values (unsorted). Returns nullopt when empty.
std::optional<DexPerfStat> make_stat(std::vector<double>& vals) {
    if (vals.empty())
        return std::nullopt;
    std::sort(vals.begin(), vals.end());
    double sum = 0.0;
    for (double v : vals)
        sum += v;
    DexPerfStat s;
    s.n = static_cast<int64_t>(vals.size());
    s.avg = sum / static_cast<double>(vals.size());
    s.p50 = nearest_rank(vals, 0.50);
    s.p90 = nearest_rank(vals, 0.90);
    s.max = vals.back();
    return s;
}

bool reports_any(const DexPerfDevice& d) {
    return d.cpu_pct.has_value() || d.commit_pct.has_value() || d.disk_lat_ms.has_value();
}

std::optional<double> metric_value(const DexPerfDevice& d, DexPerfMetric m) {
    switch (m) {
    case DexPerfMetric::kCommit:
        return d.commit_pct;
    case DexPerfMetric::kDiskLat:
        return d.disk_lat_ms;
    case DexPerfMetric::kCpu:
    default:
        return d.cpu_pct;
    }
}

} // namespace

DexPerfMetric dex_perf_metric_from_token(const std::string& token) {
    if (token == "commit")
        return DexPerfMetric::kCommit;
    if (token == "disk_lat")
        return DexPerfMetric::kDiskLat;
    return DexPerfMetric::kCpu;
}

const char* dex_perf_metric_token(DexPerfMetric m) {
    switch (m) {
    case DexPerfMetric::kCommit:
        return "commit";
    case DexPerfMetric::kDiskLat:
        return "disk_lat";
    case DexPerfMetric::kCpu:
    default:
        return "cpu";
    }
}

DexPerfFleetNow dex_perf_fleet_now(const DexPerfSnapshot& snap) {
    DexPerfFleetNow out;
    std::vector<double> cpu, commit, disk;
    for (const auto& d : snap.devices) {
        // *_online: every online device of that OS, regardless of whether it
        // reported anything this cycle. perf_capable_online (below) is the
        // coverage-honest denominator: only OSes that collect perf.
        if (d.os == "windows")
            ++out.windows_online;
        else if (d.os == "linux")
            ++out.linux_online;
        else if (d.os == "macos")
            ++out.macos_online;
        if (detail::dex_perf_os_collects(d.os))
            ++out.perf_capable_online;
        const bool reported = reports_any(d);
        if (reported) {
            ++out.reporting;
            if (d.os == "windows")
                ++out.reporting_windows;
            else if (d.os == "linux")
                ++out.reporting_linux;
            else if (d.os == "macos")
                ++out.reporting_macos;
        }
        if (d.cpu_pct)
            cpu.push_back(*d.cpu_pct);
        if (d.commit_pct)
            commit.push_back(*d.commit_pct);
        if (d.disk_lat_ms)
            disk.push_back(*d.disk_lat_ms);
    }
    out.cpu = make_stat(cpu);
    out.commit = make_stat(commit);
    out.disk_lat = make_stat(disk);
    return out;
}

std::vector<DexPerfCohortRow> dex_perf_cohorts(const DexPerfSnapshot& snap) {
    // Group REPORTING devices only — a cohort of enrolled-but-silent devices
    // has nothing to benchmark (they appear via the not-reporting drill).
    struct Acc {
        std::vector<double> cpu, commit, disk;
        int64_t devices{0};
    };
    std::map<std::string, Acc> groups; // ordered: deterministic output
    for (const auto& d : snap.devices) {
        if (!reports_any(d))
            continue;
        auto& g = groups[d.cohort];
        ++g.devices;
        if (d.cpu_pct)
            g.cpu.push_back(*d.cpu_pct);
        if (d.commit_pct)
            g.commit.push_back(*d.commit_pct);
        if (d.disk_lat_ms)
            g.disk.push_back(*d.disk_lat_ms);
    }

    std::vector<DexPerfCohortRow> rows;
    rows.reserve(groups.size());
    for (auto& [cohort, acc] : groups) {
        DexPerfCohortRow r;
        r.cohort = cohort;
        r.devices = acc.devices;
        if (acc.devices < kDexCohortFloor) {
            r.suppressed = true; // population shown, percentiles withheld
        } else {
            r.cpu = make_stat(acc.cpu);
            r.commit = make_stat(acc.commit);
            r.disk_lat = make_stat(acc.disk);
        }
        rows.push_back(std::move(r));
    }
    // Population-descending; the "(untagged)" residual (cohort == "") last so
    // it reads as the residual it is, not a competing cohort.
    std::stable_sort(rows.begin(), rows.end(),
                     [](const DexPerfCohortRow& a, const DexPerfCohortRow& b) {
                         const bool a_untagged = a.cohort.empty();
                         const bool b_untagged = b.cohort.empty();
                         if (a_untagged != b_untagged)
                             return b_untagged;
                         return a.devices > b.devices;
                     });
    return rows;
}

namespace {
/// A's p50 relative to B's p50, as a percentage (B is the baseline). Absent when
/// either side lacks the stat or B's p50 is ~0 — mirrors delta_pill's guard so
/// the diff number and the pill agree.
std::optional<double> p50_delta_pct(const std::optional<DexPerfStat>& a,
                                    const std::optional<DexPerfStat>& b) {
    if (!a || !b || b->p50 < 1e-9)
        return std::nullopt;
    return (a->p50 - b->p50) / b->p50 * 100.0;
}
} // namespace

DexPerfCohortDiff dex_perf_cohort_diff(const DexPerfSnapshot& snap, const std::string& cohort_a,
                                       const std::string& cohort_b) {
    DexPerfCohortDiff d;
    d.cohort_a = cohort_a;
    d.cohort_b = cohort_b;
    // Reuse the single cohort aggregation so the diff and the cohort table can
    // never disagree; select the two requested cohort values from its output.
    // (A == B sets both to the same row via the first match — zero deltas.)
    for (const auto& r : dex_perf_cohorts(snap)) {
        if (!d.found_a && r.cohort == cohort_a) {
            d.a = r;
            d.found_a = true;
        }
        if (!d.found_b && r.cohort == cohort_b) {
            d.b = r;
            d.found_b = true;
        }
    }
    if (d.found_a && d.found_b) {
        d.cpu_delta_pct = p50_delta_pct(d.a.cpu, d.b.cpu);
        d.commit_delta_pct = p50_delta_pct(d.a.commit, d.b.commit);
        d.disk_lat_delta_pct = p50_delta_pct(d.a.disk_lat, d.b.disk_lat);
    }
    return d;
}

void dex_perf_clear_cohort_gauges(yuzu::MetricsRegistry& metrics) {
    metrics.clear_gauge_family("yuzu_fleet_perf_cohort_cpu_pct");
    metrics.clear_gauge_family("yuzu_fleet_perf_cohort_commit_pct");
    metrics.clear_gauge_family("yuzu_fleet_perf_cohort_disk_lat_ms");
    metrics.clear_gauge_family("yuzu_fleet_perf_cohort_reporting");
    metrics.clear_gauge_family("yuzu_fleet_perf_cohort_clipped");
}

void dex_perf_export_cohort_gauges(yuzu::MetricsRegistry& metrics,
                                   const std::vector<DexPerfCohortRow>& rows, int cap) {
    dex_perf_clear_cohort_gauges(metrics);
    int exported = 0;
    int clipped = 0;
    auto set_stats = [&](const char* family, const std::string& cohort,
                         const std::optional<DexPerfStat>& s) {
        if (!s)
            return; // metric nobody in the cohort reported — absent, never 0
        metrics.gauge(family, {{"cohort", cohort}, {"stat", "avg"}}).set(s->avg);
        metrics.gauge(family, {{"cohort", cohort}, {"stat", "p50"}}).set(s->p50);
        metrics.gauge(family, {{"cohort", cohort}, {"stat", "p90"}}).set(s->p90);
        metrics.gauge(family, {{"cohort", cohort}, {"stat", "max"}}).set(s->max);
    };
    for (const auto& r : rows) {
        if (r.suppressed)
            continue; // below the statistical floor — withheld everywhere
        if (exported >= cap) {
            ++clipped;
            continue;
        }
        const std::string label = r.cohort.empty() ? "(untagged)" : r.cohort;
        set_stats("yuzu_fleet_perf_cohort_cpu_pct", label, r.cpu);
        set_stats("yuzu_fleet_perf_cohort_commit_pct", label, r.commit);
        set_stats("yuzu_fleet_perf_cohort_disk_lat_ms", label, r.disk_lat);
        metrics.gauge("yuzu_fleet_perf_cohort_reporting", {{"cohort", label}})
            .set(static_cast<double>(r.devices));
        ++exported;
    }
    // A measured zero once the export is active: "nothing was clipped" is a
    // fact Grafana alerts can rely on.
    metrics.gauge("yuzu_fleet_perf_cohort_clipped").set(static_cast<double>(clipped));
}

DexPerfDeviceContext dex_perf_device_context(const DexPerfSnapshot& snap,
                                             const std::string& agent_id) {
    DexPerfDeviceContext ctx;
    const DexPerfDevice* me = nullptr;
    for (const auto& d : snap.devices) {
        if (d.agent_id == agent_id) {
            me = &d;
            break;
        }
    }
    if (!me)
        return ctx;
    ctx.found = true;
    ctx.reporting = reports_any(*me);
    ctx.cohort = me->cohort;

    std::vector<double> fleet_cpu, fleet_commit, fleet_disk;
    std::vector<double> coh_cpu, coh_commit, coh_disk;
    for (const auto& d : snap.devices) {
        if (!reports_any(d))
            continue;
        const bool in_cohort = (d.cohort == me->cohort);
        if (in_cohort)
            ++ctx.cohort_n;
        if (d.cpu_pct) {
            fleet_cpu.push_back(*d.cpu_pct);
            if (in_cohort)
                coh_cpu.push_back(*d.cpu_pct);
        }
        if (d.commit_pct) {
            fleet_commit.push_back(*d.commit_pct);
            if (in_cohort)
                coh_commit.push_back(*d.commit_pct);
        }
        if (d.disk_lat_ms) {
            fleet_disk.push_back(*d.disk_lat_ms);
            if (in_cohort)
                coh_disk.push_back(*d.disk_lat_ms);
        }
    }

    const bool cohort_ok = ctx.cohort_n >= kDexCohortFloor;
    auto fill = [&](DexPerfMetricContext& m, std::optional<double> v, std::vector<double>& fleet,
                    std::vector<double>& cohort) {
        m.value = v;
        // Sort once; make_stat's internal sort is then a no-op pass and
        // percentile_rank (the shared value→rank helper, dex_perf_rules.hpp)
        // requires sorted input.
        std::sort(fleet.begin(), fleet.end());
        std::sort(cohort.begin(), cohort.end());
        if (v) {
            m.fleet_pctile = detail::percentile_rank(fleet, *v);
            if (cohort_ok)
                m.cohort_pctile = detail::percentile_rank(cohort, *v);
        }
        m.fleet = make_stat(fleet);
        m.cohort = cohort_ok ? make_stat(cohort) : std::nullopt;
    };
    fill(ctx.cpu, me->cpu_pct, fleet_cpu, coh_cpu);
    fill(ctx.commit, me->commit_pct, fleet_commit, coh_commit);
    fill(ctx.disk_lat, me->disk_lat_ms, fleet_disk, coh_disk);
    return ctx;
}

std::vector<DexPerfDeviceRow> dex_perf_device_list(const DexPerfSnapshot& snap, DexPerfMetric metric,
                                                   bool not_reporting,
                                                   const std::optional<std::string>& cohort_filter,
                                                   int limit) {
    if (limit <= 0)
        return {};

    // Percentile context: every reported value of the sort metric, fleet-wide
    // (NOT filtered) — "this device sits at the fleet's Nth percentile" must
    // mean the same thing from every drill. Rank via the shared
    // detail::percentile_rank (value→rank; see dex_perf_rules.hpp).
    std::vector<double> fleet_vals;
    for (const auto& d : snap.devices)
        if (auto v = metric_value(d, metric))
            fleet_vals.push_back(*v);
    std::sort(fleet_vals.begin(), fleet_vals.end());

    std::vector<DexPerfDeviceRow> rows;
    for (const auto& d : snap.devices) {
        if (cohort_filter && d.cohort != *cohort_filter)
            continue;
        if (not_reporting) {
            // The complement list: devices whose OS has a real perf collector
            // (dex_perf_os_collects) but contributed nothing this cycle.
            if (!detail::dex_perf_os_collects(d.os) || reports_any(d))
                continue;
        } else {
            if (!metric_value(d, metric))
                continue;
        }
        DexPerfDeviceRow r;
        r.agent_id = d.agent_id;
        r.cohort = d.cohort;
        r.cpu_pct = d.cpu_pct;
        r.commit_pct = d.commit_pct;
        r.disk_lat_ms = d.disk_lat_ms;
        r.os = d.os;
        if (auto v = metric_value(d, metric))
            r.fleet_pctile = detail::percentile_rank(fleet_vals, *v);
        rows.push_back(std::move(r));
    }

    if (not_reporting) {
        std::sort(rows.begin(), rows.end(), [](const DexPerfDeviceRow& a, const DexPerfDeviceRow& b) {
            return a.agent_id < b.agent_id;
        });
    } else {
        std::stable_sort(rows.begin(), rows.end(),
                         [&](const DexPerfDeviceRow& a, const DexPerfDeviceRow& b) {
                             // Both have the metric (filtered above); worst first.
                             double x = 0.0, y = 0.0;
                             switch (metric) {
                             case DexPerfMetric::kCommit:
                                 x = *a.commit_pct;
                                 y = *b.commit_pct;
                                 break;
                             case DexPerfMetric::kDiskLat:
                                 x = *a.disk_lat_ms;
                                 y = *b.disk_lat_ms;
                                 break;
                             case DexPerfMetric::kCpu:
                             default:
                                 x = *a.cpu_pct;
                                 y = *b.cpu_pct;
                                 break;
                             }
                             return x > y;
                         });
    }

    if (rows.size() > static_cast<std::size_t>(limit))
        rows.resize(static_cast<std::size_t>(limit));
    return rows;
}

} // namespace yuzu::server
