#include "network_perf_model.hpp"

#include "network_perf_rules.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server {

namespace {

using detail::nearest_rank;
using detail::net_device_under_pressure;

/// Build a NetPerfStat from raw values (unsorted). Returns nullopt when empty.
std::optional<NetPerfStat> make_stat(std::vector<double>& vals) {
    if (vals.empty())
        return std::nullopt;
    std::sort(vals.begin(), vals.end());
    double sum = 0.0;
    for (double v : vals)
        sum += v;
    NetPerfStat s;
    s.n = static_cast<int64_t>(vals.size());
    s.avg = sum / static_cast<double>(vals.size());
    s.p50 = nearest_rank(vals, 0.50);
    s.p90 = nearest_rank(vals, 0.90);
    s.max = vals.back();
    return s;
}

bool reports_any(const NetPerfDevice& d) {
    return d.rtt_ms.has_value() || d.retrans_pct.has_value() || d.throughput_bps.has_value();
}

std::optional<double> metric_value(const NetPerfDevice& d, NetPerfMetric m) {
    switch (m) {
    case NetPerfMetric::kRetrans:
        return d.retrans_pct;
    case NetPerfMetric::kThroughput:
        return d.throughput_bps;
    case NetPerfMetric::kRtt:
    default:
        return d.rtt_ms;
    }
}

std::optional<double> row_metric(const NetPerfDeviceRow& r, NetPerfMetric m) {
    switch (m) {
    case NetPerfMetric::kRetrans:
        return r.retrans_pct;
    case NetPerfMetric::kThroughput:
        return r.throughput_bps;
    case NetPerfMetric::kRtt:
    default:
        return r.rtt_ms;
    }
}

/// Membership in a co-occurrence band. Bands are over net_degraded devices
/// ONLY — a healthy device never appears, whatever else is happening on it.
bool in_cooc_band(const NetPerfDevice& d, NetCoocFilter f) {
    if (!d.net_degraded)
        return false;
    const bool pressure = net_device_under_pressure(d.cpu_pct, d.commit_pct, d.disk_lat_ms);
    switch (f) {
    case NetCoocFilter::kDegradedAll:
        return true;
    case NetCoocFilter::kAlsoDevice:
        return pressure;
    case NetCoocFilter::kAlsoApp:
        return d.app_unstable;
    case NetCoocFilter::kNetworkOnly:
        return !pressure && !d.app_unstable;
    case NetCoocFilter::kNone:
    default:
        return false;
    }
}

} // namespace

NetPerfMetric net_perf_metric_from_token(const std::string& token) {
    if (token == "retrans")
        return NetPerfMetric::kRetrans;
    if (token == "throughput")
        return NetPerfMetric::kThroughput;
    return NetPerfMetric::kRtt;
}

NetCoocFilter net_cooc_from_token(const std::string& token) {
    if (token == "device")
        return NetCoocFilter::kAlsoDevice;
    if (token == "app")
        return NetCoocFilter::kAlsoApp;
    if (token == "network_only")
        return NetCoocFilter::kNetworkOnly;
    if (token == "degraded")
        return NetCoocFilter::kDegradedAll;
    return NetCoocFilter::kNone;
}

const char* net_perf_metric_token(NetPerfMetric m) {
    switch (m) {
    case NetPerfMetric::kRetrans:
        return "retrans";
    case NetPerfMetric::kThroughput:
        return "throughput";
    case NetPerfMetric::kRtt:
    default:
        return "rtt";
    }
}

NetPerfFleetNow net_perf_fleet_now(const NetPerfSnapshot& snap) {
    NetPerfFleetNow out;
    out.available_keys = snap.available_keys;
    std::vector<double> rtt, retrans, tput;
    for (const auto& d : snap.devices) {
        ++out.online;
        if (reports_any(d))
            ++out.reporting;
        if (d.rtt_ms) {
            ++out.rtt_reporting; // RTT carries its own (smaller) denominator — honesty
            rtt.push_back(*d.rtt_ms);
        }
        if (d.retrans_pct)
            retrans.push_back(*d.retrans_pct);
        if (d.throughput_bps)
            tput.push_back(*d.throughput_bps);
        // Count degraded only for devices that actually reported a metric this
        // cycle, so a forged net_degraded=1 with no valid metric can never make
        // the co-occurrence headline exceed the Reporting denominator (UP-9).
        if (d.net_degraded && reports_any(d)) {
            ++out.cooc.degraded;
            const bool pressure =
                net_device_under_pressure(d.cpu_pct, d.commit_pct, d.disk_lat_ms);
            if (pressure)
                ++out.cooc.also_device;
            if (d.app_unstable)
                ++out.cooc.also_app;
            if (!pressure && !d.app_unstable)
                ++out.cooc.network_only;
        }
    }
    out.rtt = make_stat(rtt);
    out.retrans = make_stat(retrans);
    out.throughput = make_stat(tput);
    return out;
}

std::vector<NetPerfDeviceRow> net_perf_device_list(const NetPerfSnapshot& snap, NetPerfMetric metric,
                                                   bool not_reporting, NetCoocFilter cooc,
                                                   const std::optional<std::string>& cohort_filter,
                                                   int limit) {
    if (limit <= 0)
        return {};

    // Percentile context: every reported value of the sort metric, fleet-wide
    // (NOT filtered) — "this device sits at the fleet's Nth percentile" must
    // mean the same thing from every drill. Shared detail::percentile_rank.
    std::vector<double> fleet_vals;
    for (const auto& d : snap.devices)
        if (auto v = metric_value(d, metric))
            fleet_vals.push_back(*v);
    std::sort(fleet_vals.begin(), fleet_vals.end());

    std::vector<NetPerfDeviceRow> rows;
    for (const auto& d : snap.devices) {
        if (cohort_filter && d.cohort != *cohort_filter)
            continue;
        if (not_reporting) {
            if (reports_any(d))
                continue; // cross-platform complement: any device with no metric
        } else if (cooc != NetCoocFilter::kNone) {
            if (!in_cooc_band(d, cooc))
                continue;
        } else {
            if (!metric_value(d, metric))
                continue;
        }
        NetPerfDeviceRow r;
        r.agent_id = d.agent_id;
        r.platform = d.platform;
        r.cohort = d.cohort;
        r.rtt_ms = d.rtt_ms;
        r.retrans_pct = d.retrans_pct;
        r.throughput_bps = d.throughput_bps;
        r.net_degraded = d.net_degraded;
        r.under_pressure = net_device_under_pressure(d.cpu_pct, d.commit_pct, d.disk_lat_ms);
        r.app_unstable = d.app_unstable;
        if (auto v = metric_value(d, metric))
            r.fleet_pctile = detail::percentile_rank(fleet_vals, *v);
        rows.push_back(std::move(r));
    }

    if (not_reporting) {
        std::sort(rows.begin(), rows.end(), [](const NetPerfDeviceRow& a, const NetPerfDeviceRow& b) {
            return a.agent_id < b.agent_id;
        });
    } else {
        // Worst-first by the sort metric; rows missing the metric sort last
        // (stable, so their relative order is the snapshot order). Higher is
        // "worse" for RTT/retransmit and "busiest" for throughput.
        std::stable_sort(rows.begin(), rows.end(),
                         [&](const NetPerfDeviceRow& a, const NetPerfDeviceRow& b) {
                             const auto av = row_metric(a, metric);
                             const auto bv = row_metric(b, metric);
                             if (av.has_value() != bv.has_value())
                                 return av.has_value(); // present before absent
                             if (!av.has_value())
                                 return false;
                             return *av > *bv;
                         });
    }

    if (rows.size() > static_cast<std::size_t>(limit))
        rows.resize(static_cast<std::size_t>(limit));
    return rows;
}

} // namespace yuzu::server
