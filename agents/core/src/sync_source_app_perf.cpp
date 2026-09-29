#include "sync_source_app_perf.hpp"

#include "local_dispatcher.hpp"
#include "sync_canonical.hpp" // sha256_hex (shared agent util)

#include <yuzu/version_string.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string_view>
#include <utility>

namespace yuzu::agent {

namespace {

// Total wire-blob ceiling — MUST equal the server seam's kMaxBlobBytes
// (app_perf_ingestion.cpp); comment-coordinated, below the 4 MiB gRPC ceiling.
// The real payload is ~tens of KB (≤2 days × top-N × a few versions).
constexpr std::size_t kMaxBlobBytes = 1u * 1024 * 1024;

std::int64_t parse_i64(std::string_view s) {
    std::int64_t v = 0;
    const auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    (void)p;
    return ec == std::errc{} ? v : 0;
}

double parse_double(std::string_view s) {
    // libc++ on Apple Clang 15 (the macOS agent rig) has no floating-point
    // std::from_chars (docs/ci-cpp23-troubleshooting.md); std::stod is the portable
    // form used across the codebase. Integer from_chars (parse_i64) is fine.
    if (s.empty() || s.size() > 64)
        return 0.0;
    try {
        const std::string tmp(s);
        std::size_t pos = 0;
        const double v = std::stod(tmp, &pos);
        if (pos == tmp.size() && std::isfinite(v))
            return v;
    } catch (...) {
    }
    return 0.0;
}

double clamp_finite_nonneg(double v) {
    return (std::isfinite(v) && v > 0.0) ? v : 0.0;
}

// Locale-independent double formatting ('.' decimal regardless of locale).
std::string fmt_double(double v) {
    return std::format("{}", v);
}

// Strip the wire framing bytes (and NUL) so a value can never corrupt the blob's
// 0x1F/0x1E structure or the libpq text param. Process image names never contain
// these; this is defence-in-depth.
void append_clean(std::string& out, std::string_view v) {
    for (char c : v)
        if (c != '\x1f' && c != '\x1e' && c != '\0' && c != '\n' && c != '\r')
            out.push_back(c);
}

} // namespace

std::string build_app_perf_query(std::int64_t window_start, std::int64_t today_start) {
    // Column order here IS the wire/parse contract (parse_app_perf_sql_output reads
    // positionally). Sample-weighted averages reconstruct the true daily mean from
    // procperf_hourly's per-hour AVG×COUNT; max-of-max for peaks; SUM for counts.
    // $ProcPerf_Hourly is translated to procperf_hourly by the TAR sql validator.
    // `AND NOT is_kthread` excludes Linux kernel threads (PF_KTHREAD) and the
    // Windows System process (pid 4) from the daily app-perf-over-time
    // history — see tar_proc_perf.hpp's "Kernel-thread marker" note. This is
    // the ONLY consumer that filters on the flag: the live TAR procperf tiers
    // this query reads FROM keep kernel threads unfiltered by design.
    return std::format(
        "SELECT name, version, (hour_ts/86400)*86400 AS day, "
        "SUM(samples) AS samples, MAX(instances_max) AS instances_max, "
        "SUM(cpu_avg*samples)/SUM(samples) AS cpu_avg, MAX(cpu_max) AS cpu_max, "
        "SUM(ws_avg_bytes*samples)/SUM(samples) AS ws_avg_bytes, MAX(ws_max_bytes) AS ws_max_bytes "
        "FROM $ProcPerf_Hourly "
        "WHERE hour_ts >= {} AND hour_ts < {} AND NOT is_kthread "
        "GROUP BY name, version, (hour_ts/86400)*86400",
        window_start, today_start);
}

std::vector<AppPerfRow> parse_app_perf_sql_output(const std::string& captured) {
    std::vector<AppPerfRow> out;
    std::size_t pos = 0;
    while (pos < captured.size()) {
        std::size_t eol = captured.find('\n', pos);
        if (eol == std::string::npos)
            eol = captured.size();
        std::string_view line(captured.data() + pos, eol - pos);
        while (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        pos = eol + 1;
        if (line.empty() || line.starts_with("__schema__") || line.starts_with("__total__") ||
            line.starts_with("error|"))
            continue;

        std::string_view tok[9]; // value-initialised to empty views
        std::size_t ti = 0;
        std::size_t fp = 0;
        while (ti < 9) {
            std::size_t bar = line.find('|', fp);
            if (bar == std::string_view::npos) {
                tok[ti++] = line.substr(fp);
                break;
            }
            tok[ti++] = line.substr(fp, bar - fp);
            fp = bar + 1;
        }
        if (ti < 3) // need at least name, version, day to be a real row
            continue;

        AppPerfRow r;
        r.name = std::string(tok[0]);
        r.version = std::string(tok[1]);
        r.day = parse_i64(tok[2]);
        r.samples = parse_i64(tok[3]);
        r.instances_max = parse_i64(tok[4]);
        r.cpu_avg = parse_double(tok[5]);
        r.cpu_max = parse_double(tok[6]);
        r.ws_avg_bytes = parse_i64(tok[7]);
        r.ws_max_bytes = parse_i64(tok[8]);
        if (r.name.empty() || r.day <= 0)
            continue;
        out.push_back(std::move(r));
    }
    return out;
}

std::vector<AppPerfRow> canon_merge_app_perf(std::vector<AppPerfRow> rows) {
    for (auto& r : rows) {
        r.version = yuzu::util::canon_version(r.version);
        r.cpu_avg = clamp_finite_nonneg(r.cpu_avg);
        r.cpu_max = clamp_finite_nonneg(r.cpu_max);
        if (r.samples < 0)
            r.samples = 0;
        if (r.instances_max < 0)
            r.instances_max = 0;
        if (r.ws_avg_bytes < 0)
            r.ws_avg_bytes = 0;
        if (r.ws_max_bytes < 0)
            r.ws_max_bytes = 0;
    }
    std::sort(rows.begin(), rows.end(), [](const AppPerfRow& a, const AppPerfRow& b) {
        if (a.name != b.name)
            return a.name < b.name;
        if (a.version != b.version)
            return a.version < b.version;
        return a.day < b.day;
    });
    std::vector<AppPerfRow> out;
    out.reserve(rows.size());
    for (auto& r : rows) {
        if (!out.empty() && out.back().name == r.name && out.back().version == r.version &&
            out.back().day == r.day) {
            AppPerfRow& m = out.back();
            const std::int64_t total = m.samples + r.samples;
            if (total > 0) {
                m.cpu_avg = (m.cpu_avg * static_cast<double>(m.samples) +
                             r.cpu_avg * static_cast<double>(r.samples)) /
                            static_cast<double>(total);
                const long double wavg =
                    (static_cast<long double>(m.ws_avg_bytes) * static_cast<long double>(m.samples) +
                     static_cast<long double>(r.ws_avg_bytes) * static_cast<long double>(r.samples)) /
                    static_cast<long double>(total);
                m.ws_avg_bytes = static_cast<std::int64_t>(wavg);
            }
            m.samples = total;
            m.cpu_max = std::max(m.cpu_max, r.cpu_max);
            m.ws_max_bytes = std::max(m.ws_max_bytes, r.ws_max_bytes);
            m.instances_max = std::max(m.instances_max, r.instances_max);
        } else {
            out.push_back(std::move(r));
        }
    }
    return out;
}

std::string render_app_perf_blob(std::vector<AppPerfRow> rows) {
    std::string blob;
    blob.reserve(rows.size() * 64);
    for (const auto& r : rows) {
        append_clean(blob, r.name);
        blob += '\x1f';
        append_clean(blob, r.version);
        blob += '\x1f';
        blob += std::to_string(r.day);
        blob += '\x1f';
        blob += std::to_string(r.samples);
        blob += '\x1f';
        blob += std::to_string(r.instances_max);
        blob += '\x1f';
        blob += fmt_double(r.cpu_avg);
        blob += '\x1f';
        blob += fmt_double(r.cpu_max);
        blob += '\x1f';
        blob += std::to_string(r.ws_avg_bytes);
        blob += '\x1f';
        blob += std::to_string(r.ws_max_bytes);
        blob += '\x1e';
    }
    return blob;
}

SyncSource make_app_perf_source(const YuzuPluginDescriptor* tar_descriptor) {
    SyncSource src;
    src.name = "app_perf";
    src.interval = std::chrono::hours{24};
    src.collect = [tar_descriptor]() -> std::optional<std::pair<std::string, std::string>> {
        if (tar_descriptor == nullptr) {
            spdlog::debug("sync: TAR plugin not loaded — app_perf source idle");
            return std::nullopt;
        }
        const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count();
        const std::int64_t today_start = (now / 86400) * 86400;
        const std::int64_t window_start = today_start - 2 * 86400; // 2 completed UTC days

        const std::string sql = build_app_perf_query(window_start, today_start);
        const YuzuParam params[1] = {{"sql", sql.c_str()}};
        LocalDispatcher dispatcher;
        LocalDispatcher::Result r =
            dispatcher.run(tar_descriptor, "sql", std::span<const YuzuParam>(params, 1));
        if (r.rc != 0) {
            spdlog::warn("sync: TAR 'sql' rc={} for app_perf rollup — skipping this cycle", r.rc);
            return std::nullopt;
        }
        if (r.truncated) {
            spdlog::warn("sync: TAR 'sql' app_perf output truncated at the capture cap — "
                         "skipping this cycle");
            return std::nullopt;
        }
        std::vector<AppPerfRow> rows = parse_app_perf_sql_output(r.captured);
        if (rows.empty()) {
            // No top-N activity / procperf disabled — skip (network-kind: never send
            // an empty blob). A device's stale rows are bounded ≤31d server-side.
            spdlog::debug("sync: app_perf rollup yielded no rows — skipping this cycle");
            return std::nullopt;
        }
        std::string blob = render_app_perf_blob(canon_merge_app_perf(std::move(rows)));
        if (blob.size() > kMaxBlobBytes) {
            spdlog::warn("sync: app_perf blob {} B exceeds {} B cap — skipping this cycle",
                         blob.size(), kMaxBlobBytes);
            return std::nullopt;
        }
        std::string hash = sha256_hex(blob);
        return std::make_pair(std::move(blob), std::move(hash));
    };
    return src;
}

} // namespace yuzu::agent
